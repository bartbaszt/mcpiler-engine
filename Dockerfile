# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build

ARG TARGETARCH

WORKDIR /src

COPY .editorconfig global.json Directory.Build.props Directory.Packages.props BannedSymbols.txt ./
COPY src/MCPiler.Engine/MCPiler.Engine.csproj src/MCPiler.Engine/
COPY src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj src/MCPiler.Engine.Host/

RUN case "$TARGETARCH" in \
        amd64|'') runtime_arch=x64 ;; \
        arm64) runtime_arch=arm64 ;; \
        *) echo "Unsupported target architecture: $TARGETARCH" >&2; exit 64 ;; \
    esac \
    && dotnet restore src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj -a "$runtime_arch"

COPY src/ src/

RUN case "$TARGETARCH" in \
        amd64|'') runtime_arch=x64 ;; \
        arm64) runtime_arch=arm64 ;; \
        *) echo "Unsupported target architecture: $TARGETARCH" >&2; exit 64 ;; \
    esac \
    && dotnet publish src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj \
        -c Release \
        -a "$runtime_arch" \
        --no-restore \
        -o /out \
        -p:UseAppHost=false \
    && mkdir -p /volume

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra AS runtime

WORKDIR /app

COPY --from=build --chown=app:app /out/ ./
COPY --from=build --chown=app:app /volume/ /data/

ENV ASPNETCORE_HTTP_PORTS=8080

EXPOSE 8080
VOLUME ["/data"]

USER app

ENTRYPOINT ["dotnet", "mcpiler-engine.dll"]
CMD ["serve"]
