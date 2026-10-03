# ── cmd: self (cac self-management, like "uv self") ──────────────

_SELF_REPO="https://raw.githubusercontent.com/nmhjklnm/cac/master"

_self_cmd_update() {
    local method; method=$(_install_method)

    echo "Updating cac ..."
    _timer_start

    case "$method" in
        npm)
            echo "  Install method: $(_cyan "npm")"
            npm update -g claude-cac 2>&1 || _die "npm update failed"
            ;;
        bash)
            echo "  Install method: $(_cyan "bash")"
            (
                set -o pipefail
                curl -fsSL "$_SELF_REPO/install.sh" | CAC_DIR="$CAC_DIR" bash
            ) || _die "update failed"
            ;;
        *)
            _die "unknown install method\n  Reinstall with: curl -fsSL $_SELF_REPO/install.sh | bash"
            ;;
    esac

    local elapsed; elapsed=$(_timer_elapsed)
    echo "$(_green_bold "Updated") cac $(_dim "in $elapsed")"
}

cmd_self() {
    case "${1:-help}" in
        update)          _self_cmd_update ;;
        delete|remove)   cmd_delete ;;
        help|-h|--help)
            echo "$(_bold "cac self") — cac self-management"
            echo
            echo "  $(_bold "update")    Update cac to the latest version"
            echo "  $(_bold "delete")    Uninstall cac completely"
            ;;
        *) _die "unknown: cac self $1" ;;
    esac
}
