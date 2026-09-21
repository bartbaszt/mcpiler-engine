# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build

ARG TARGETARCH
ARG ENGINE_VERSION
ARG SOURCE_REVISION=local

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
    && project_version="$(sed -n 's:.*<Version>\([^<]*\)</Version>.*:\1:p' src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj | head -n 1)" \
    && publish_version="${ENGINE_VERSION:-$project_version}" \
    && test "$publish_version" = "$project_version" \
    && dotnet publish src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj \
        -c Release \
        -a "$runtime_arch" \
        --no-restore \
        -o /out \
        -p:UseAppHost=false \
        -p:InformationalVersion="$publish_version+$SOURCE_REVISION" \
    && mkdir -p /volume/files /volume/runtime-state

FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra AS runtime

ARG ENGINE_VERSION
ARG SOURCE_REVISION
ARG SOURCE_URL=https://github.com/bartbaszt/mcpiler-engine
ARG DOCUMENTATION_URL=https://github.com/bartbaszt/mcpiler-engine/blob/main/docs/hosting.md

WORKDIR /app

COPY --from=build --chown=app:app /out/ ./
COPY --from=build --chown=app:app /volume/ /data/
COPY --chown=app:app LICENSE NOTICE THIRD-PARTY-NOTICES.md /licenses/mcpiler-engine/

# The .NET runtime base image's own redistribution material remains inherited at:
# /usr/share/dotnet/LICENSE.txt and /usr/share/dotnet/ThirdPartyNotices.txt.
LABEL org.opencontainers.image.source="$SOURCE_URL" \
      org.opencontainers.image.revision="$SOURCE_REVISION" \
      org.opencontainers.image.version="$ENGINE_VERSION" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.title="MCPiler Engine" \
      org.opencontainers.image.description="MCPiler public MCP resource runtime" \
      org.opencontainers.image.documentation="$DOCUMENTATION_URL"

ENV ASPNETCORE_HTTP_PORTS=8080

EXPOSE 8080
VOLUME ["/data"]

USER app

ENTRYPOINT ["dotnet", "mcpiler-engine.dll"]
CMD ["serve"]
