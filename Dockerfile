# The official PowerShell image is used only to format the collected JSON.
# Host network and registry checks run in networkcheck.ps1 on Windows.
FROM mcr.microsoft.com/powershell:latest
ENV POWERSHELL_TELEMETRY_OPTOUT=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    POWERSHELL_UPDATECHECK=Off \
    HOME=/tmp
WORKDIR /app
COPY networkcheck.ps1 /app/networkcheck.ps1
USER 65532:65532
ENTRYPOINT ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", "/app/networkcheck.ps1", "--render", "/reports/.networkcheck-input.json"]
