# Package

version       = "0.1.0"
author        = "Mike A."
description   = "Fixes 1Password's SSH agent to intelligently provide your keys if you have many"
license       = "GPL-3.0-or-later"
srcDir        = "src"
bin           = @["op_ssh_fix"]


# Dependencies

requires "nim >= 1.6.12"
requires "nimsha2 >= 0.1.1"
requires "cligen >= 1.6.4"
