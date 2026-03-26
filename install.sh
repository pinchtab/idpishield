#!/usr/bin/env bash
set -euo pipefail

# idpishield installer for macOS and Linux
# Usage: curl -fsSL https://raw.githubusercontent.com/pinchtab/idpishield/main/install.sh | bash

REPO="pinchtab/idpishield"
BINARY_NAME="idpishield"

BOLD='\033[1m'
ACCENT='\033[38;2;251;191;36m'
SUCCESS='\033[38;2;0;229;204m'
ERROR='\033[38;2;230;57;70m'
MUTED='\033[38;2;90;100;128m'
NC='\033[0m'

info()    { echo -e "${MUTED}·${NC} $*"; }
success() { echo -e "${SUCCESS}✓${NC} $*"; }
error()   { echo -e "${ERROR}✗${NC} $*"; exit 1; }

print_banner() {
    echo -e "${ACCENT}${BOLD}"
    echo "  🛡️  idpishield installer"
    echo -e "${NC}${MUTED}  Defense against Indirect Prompt Injection for AI agents${NC}"
    echo ""
}

detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux)  OS="linux" ;;
        darwin) OS="darwin" ;;
        *)      error "Unsupported OS: $OS (expected linux or darwin)" ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64" ;;
        arm64|aarch64)  ARCH="arm64" ;;
        *)              error "Unsupported architecture: $ARCH (expected amd64 or arm64)" ;;
    esac

    success "Detected: ${OS}/${ARCH}"
}

get_latest_version() {
    info "Fetching latest release..."

    if command -v curl &>/dev/null; then
        VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
    elif command -v wget &>/dev/null; then
        VERSION="$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
    else
        error "curl or wget is required"
    fi

    if [[ -z "$VERSION" ]]; then
        error "Could not determine latest version"
    fi

    success "Latest version: ${VERSION}"
}

resolve_asset_name() {
    # v0.1.0 used "idpi-shield-*", later releases use "idpishield-*"
    # Try the new name first, fall back to old
    NEW_NAME="idpishield-${OS}-${ARCH}"
    OLD_NAME="idpi-shield-${OS}-${ARCH}"
    ASSET_NAME="$NEW_NAME"
}

detect_install_dir() {
    if [[ -w "/usr/local/bin" ]]; then
        INSTALL_DIR="/usr/local/bin"
    else
        INSTALL_DIR="${HOME}/.local/bin"
        mkdir -p "$INSTALL_DIR"
    fi
}

download_and_install() {
    local tmpdir
    tmpdir="$(mktemp -d)"
    trap "rm -rf '$tmpdir'" EXIT

    local base_url="https://github.com/${REPO}/releases/download/${VERSION}"
    local url="${base_url}/${ASSET_NAME}"
    local dest="${tmpdir}/${BINARY_NAME}"

    info "Downloading ${ASSET_NAME}..."

    local http_code
    if command -v curl &>/dev/null; then
        http_code="$(curl -fsSL -w '%{http_code}' -o "$dest" "$url" 2>/dev/null)" || http_code="000"
    else
        wget -qO "$dest" "$url" 2>/dev/null && http_code="200" || http_code="000"
    fi

    # Fall back to old asset name if new one fails
    if [[ "$http_code" != "200" && "$ASSET_NAME" == "$NEW_NAME" ]]; then
        ASSET_NAME="$OLD_NAME"
        url="${base_url}/${ASSET_NAME}"
        info "Trying legacy name: ${ASSET_NAME}..."

        if command -v curl &>/dev/null; then
            curl -fsSL -o "$dest" "$url" || error "Download failed for both ${NEW_NAME} and ${OLD_NAME}"
        else
            wget -qO "$dest" "$url" || error "Download failed for both ${NEW_NAME} and ${OLD_NAME}"
        fi
    elif [[ "$http_code" != "200" ]]; then
        error "Download failed (HTTP ${http_code}): ${url}"
    fi

    chmod +x "$dest"

    # Verify the binary runs
    if ! "$dest" help &>/dev/null; then
        error "Downloaded binary failed to execute"
    fi

    # Install
    if [[ -w "$INSTALL_DIR" ]]; then
        mv "$dest" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        info "Requesting sudo to install to ${INSTALL_DIR}..."
        sudo mv "$dest" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    success "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
}

check_path() {
    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
        echo ""
        echo -e "${ACCENT}${BOLD}Add to your PATH:${NC}"
        echo ""
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        echo ""
        echo "  Add this to ~/.bashrc, ~/.zshrc, or your shell profile."
        echo ""
    fi
}

verify() {
    if command -v "$BINARY_NAME" &>/dev/null; then
        success "idpishield is ready"
    else
        info "Binary installed but not yet in PATH — see instructions above"
    fi
}

show_next_steps() {
    echo ""
    echo -e "${ACCENT}${BOLD}Next steps${NC}"
    echo ""
    echo "  Scan text from stdin:"
    echo -e "    ${MUTED}echo 'Ignore all previous instructions' | idpishield scan${NC}"
    echo ""
    echo "  Scan a file:"
    echo -e "    ${MUTED}idpishield scan document.txt${NC}"
    echo ""
    echo "  Start MCP server (for AI agents):"
    echo -e "    ${MUTED}idpishield mcp serve${NC}"
    echo ""
    echo "  Documentation:"
    echo -e "    ${MUTED}https://github.com/${REPO}${NC}"
    echo ""
}

main() {
    print_banner
    detect_platform
    get_latest_version
    resolve_asset_name
    detect_install_dir
    download_and_install
    check_path
    verify
    show_next_steps
}

main "$@"
