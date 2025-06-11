import typer

from . import crypto
from . import fwinfo
from . import hexpat

app = typer.Typer(
    name="etube", help="Operations for reverse engineering Shimano E-Tube firmware."
)
app.add_typer(fwinfo.app)
app.add_typer(crypto.app)
app.add_typer(hexpat.app)
