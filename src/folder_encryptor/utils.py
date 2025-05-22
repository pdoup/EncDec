import builtins
from typing import Callable


class PrintToggler:
    def __init__(self):
        self.original_print: Callable = builtins.print
        self.console_printer: Callable = self.original_print
        self.silenced: bool = False

    def toggle_quiet(self, quiet: bool):
        if quiet and not self.silenced:
            self.console_printer = lambda *a, **kw: None
            builtins.print = self.console_printer
            self.silenced = True
        elif not quiet and self.silenced:
            self.console_printer = self.original_print
            builtins.print = self.console_printer
            self.silenced = False
