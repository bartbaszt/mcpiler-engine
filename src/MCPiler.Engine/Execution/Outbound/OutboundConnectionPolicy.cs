using System.Net;
using System.Net.Sockets;

namespace MCPiler.Engine.Execution.Outbound;

/// <summary>
/// The address ranges an upstream connection must never reach, and the connect-time decision
/// that enforces them.
/// </summary>
/// <remarks>
/// <para>
/// Containment operates on concrete addresses, never on host text. A hostname is an
/// indirection an upstream controls: it can resolve to one address when a check runs and
/// another when a socket opens, and it can be spelled in notations no two parsers agree about.
/// Resolving once and validating every answer before connecting to a validated one removes both
/// the race and the spelling question, because the address that would be connected to is the
/// address that was judged.
/// </para>
/// <para>
/// The table is duplicated from the compiling host rather than shared, like every other value
/// that crosses this boundary. The ranges are the published reservations, so two independently
/// maintained copies of them are checkable against the registries rather than against each
/// other.
/// </para>
/// </remarks>
public static class OutboundAddressPolicy
{
    // IPv4 reservations: unspecified, private, carrier NAT, loopback, link-local (which is
    // where cloud instance metadata lives at 169.254.169.254), protocol assignments,
    // documentation, anycast relay, benchmarking, multicast, reserved, broadcast.
    private static readonly IPNetwork[] DeniedV4 =
    [
        IPNetwork.Parse("0.0.0.0/8"),
        IPNetwork.Parse("10.0.0.0/8"),
        IPNetwork.Parse("100.64.0.0/10"),
        IPNetwork.Parse("127.0.0.0/8"),
        IPNetwork.Parse("169.254.0.0/16"),
        IPNetwork.Parse("172.16.0.0/12"),
        IPNetwork.Parse("192.0.0.0/24"),
        IPNetwork.Parse("192.0.2.0/24"),
        IPNetwork.Parse("192.88.99.0/24"),
        IPNetwork.Parse("192.168.0.0/16"),
        IPNetwork.Parse("198.18.0.0/15"),
        IPNetwork.Parse("198.51.100.0/24"),
        IPNetwork.Parse("203.0.113.0/24"),
        IPNetwork.Parse("224.0.0.0/4"),
        IPNetwork.Parse("240.0.0.0/4"),
        IPNetwork.Parse("255.255.255.255/32"),
    ];

    // Pure IPv6 reservations: unspecified, loopback, discard, documentation, unique local,
    // link-local, multicast. Forms carrying an embedded IPv4 address are handled by the unmap
    // path below rather than by listing their prefixes here.
    private static readonly IPNetwork[] DeniedV6 =
    [
        IPNetwork.Parse("::/128"),
        IPNetwork.Parse("::1/128"),
        IPNetwork.Parse("100::/64"),
        IPNetwork.Parse("2001:db8::/32"),
        IPNetwork.Parse("fc00::/7"),
        IPNetwork.Parse("fe80::/10"),
        IPNetwork.Parse("ff00::/8"),
    ];

    private static readonly HashSet<string> MetadataHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "metadata.google.internal",
        "metadata.azure.internal",
        "metadata",
        "metadata.internal",
        "instance-data",
        "instance-data.ec2.internal",
    };

    /// <summary>True when a concrete address must never be connected to.</summary>
    public static bool IsDenied(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            return ContainsAnyV4(address.MapToIPv4());
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return ContainsAnyV4(address);
        }

        if (ContainsAnyV6(address))
        {
            return true;
        }

        // The local-use NAT64 prefix 64:ff9b:1::/48 embeds an IPv4 address at a position the
        // operator chooses, so no translation this code could perform would be correct. The
        // whole prefix is refused instead of guessing an embedding, which fails closed.
        if (address.AddressFamily == AddressFamily.InterNetworkV6
            && StartsWith(address, [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01]))
        {
            return true;
        }

        var embedded = TryExtractEmbeddedV4(address);
        return embedded is not null && ContainsAnyV4(embedded);
    }

    /// <summary>
    /// True when a host name is a known instance-metadata name, or is an address literal in a
    /// denied range.
    /// </summary>
    /// <remarks>
    /// This is a convenience for a caller holding text, not the containing control. A metadata
    /// name usually resolves into link-local space and is refused by
    /// <see cref="IsDenied(IPAddress)"/> anyway; naming the well-known ones lets a refusal say
    /// what it refused.
    /// </remarks>
    public static bool IsDeniedHostName(string hostName)
    {
        ArgumentNullException.ThrowIfNull(hostName);

        var normalized = hostName.TrimEnd('.');

        if (MetadataHosts.Contains(normalized))
        {
            return true;
        }

        return IPAddress.TryParse(normalized, out var literal) && IsDenied(literal);
    }

    private static bool ContainsAnyV4(IPAddress candidate)
    {
        foreach (var network in DeniedV4)
        {
            if (network.Contains(candidate))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsAnyV6(IPAddress candidate)
    {
        foreach (var network in DeniedV6)
        {
            if (network.Contains(candidate))
            {
                return true;
            }
        }

        return false;
    }

    private static bool StartsWith(IPAddress candidate, byte[] prefix)
    {
        var bytes = candidate.GetAddressBytes();
        if (bytes.Length != 16)
        {
            return false;
        }

        for (var index = 0; index < prefix.Length; index++)
        {
            if (bytes[index] != prefix[index])
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// The IPv4 address embedded in a 6to4 (<c>2002::/16</c>), well-known NAT64
    /// (<c>64:ff9b::/96</c>) or IPv4-compatible (<c>::/96</c>) address, or null.
    /// </summary>
    private static IPAddress? TryExtractEmbeddedV4(IPAddress candidate)
    {
        var bytes = candidate.GetAddressBytes();
        if (bytes.Length != 16)
        {
            return null;
        }

        // 6to4: 2002:V4:V4::
        if (bytes[0] == 0x20 && bytes[1] == 0x02)
        {
            return new IPAddress([bytes[2], bytes[3], bytes[4], bytes[5]]);
        }

        // NAT64 well-known prefix, whose /96 layout puts the address in the final 32 bits.
        if (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b
            && bytes[4] == 0x00 && bytes[5] == 0x00 && bytes[6] == 0x00 && bytes[7] == 0x00
            && bytes[8] == 0x00 && bytes[9] == 0x00 && bytes[10] == 0x00 && bytes[11] == 0x00)
        {
            return new IPAddress(bytes[12..16]);
        }

        // IPv4-compatible ::/96. The all-zero address is already denied as IPv6.
        for (var index = 0; index < 12; index++)
        {
            if (bytes[index] != 0)
            {
                return null;
            }
        }

        return bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] == 0
            ? null
            : new IPAddress(bytes[12..16]);
    }
}

/// <summary>
/// Decides whether one resolved address is refused.
/// </summary>
/// <remarks>
/// Production always uses <see cref="OutboundConnectionPolicy.DefaultGuard"/>. The delegate
/// exists because loopback is a denied range and every in-process test server lives there: a
/// test that has to observe a real connection substitutes the judgement instead of weakening
/// the shipped table, so the table's own tests keep asserting what production does.
/// </remarks>
/// <param name="address">The concrete address a socket would be opened to.</param>
public delegate bool OutboundAddressGuard(IPAddress address);

/// <summary>
/// The only place in Engine that opens an upstream socket.
/// </summary>
/// <remarks>
/// Resolution happens once. Every answer is judged. The connection is made to an answer that
/// was judged, and to nothing else — not to a re-resolved name, and not to an address obtained
/// after the judgement.
/// </remarks>
public sealed class OutboundConnectionPolicy
{
    /// <summary>The shipped judgement: the published reservation table.</summary>
    public static OutboundAddressGuard DefaultGuard { get; } = OutboundAddressPolicy.IsDenied;

    private readonly OutboundAddressGuard _isDenied;

    /// <summary>Creates a policy using the shipped address table.</summary>
    public OutboundConnectionPolicy()
        : this(DefaultGuard)
    {
    }

    /// <summary>Creates a policy using <paramref name="isDenied"/> as the address judgement.</summary>
    public OutboundConnectionPolicy(OutboundAddressGuard isDenied)
    {
        ArgumentNullException.ThrowIfNull(isDenied);
        _isDenied = isDenied;
    }

    /// <summary>True when this policy is the shipped one.</summary>
    public bool UsesDefaultGuard => _isDenied == DefaultGuard;

    /// <summary>
    /// Opens a connection to <paramref name="host"/> and <paramref name="port"/> through a
    /// validated address.
    /// </summary>
    /// <remarks>
    /// A refusal by the address judgement throws before any socket exists. A connect failure
    /// after a successful judgement is a transport fault and is reported as one: the two are
    /// different findings and an operator correcting the wrong one is a diagnosis failure.
    /// </remarks>
    public async ValueTask<Stream> ConnectAsync(string host, int port, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);

        var addresses = await ResolveValidatedAsync(host, cancellationToken).ConfigureAwait(false);

        Exception? lastConnectError = null;
        foreach (var address in addresses)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true,
            };

            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, port), cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                lastConnectError = ex;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        throw lastConnectError is null
            ? new HostResolutionException(host)
            : new UpstreamTransportException(
                $"No resolved address for '{host}' accepted a connection on port {port}.",
                lastConnectError);
    }

    /// <summary>
    /// Resolves <paramref name="host"/> once and returns every answer, having refused the whole
    /// host if any answer is denied.
    /// </summary>
    /// <remarks>
    /// Fail-closed on any denied answer rather than filtering to the permitted ones. A name
    /// answering with both a public and a private address is a name whose meaning depends on
    /// which answer a resolver happens to return first, and connecting to the acceptable half
    /// of an ambiguous answer is how a rebinding attempt succeeds on the second attempt.
    /// </remarks>
    public async Task<IReadOnlyList<IPAddress>> ResolveValidatedAsync(string host, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);

        IPAddress[] addresses;

        if (IPAddress.TryParse(host, out var literal))
        {
            // A literal is already concrete: no resolution can change what would be connected
            // to, and the notation it was written in is irrelevant once it is parsed.
            addresses = [literal];
        }
        else
        {
            try
            {
                addresses = await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false) ?? [];
            }
            catch (Exception ex) when (ex is SocketException or ArgumentException)
            {
                throw new HostResolutionException(host, ex);
            }

            if (addresses.Length == 0)
            {
                throw new HostResolutionException(host);
            }
        }

        foreach (var address in addresses)
        {
            if (_isDenied(address))
            {
                throw new AddressPolicyViolationException(host, address.ToString());
            }
        }

        return addresses;
    }
}
