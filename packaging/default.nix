# The chain's Nix expression is xrd-devtools' (packaging/nix there); this
# builds xgfalclient from this checkout with it. The xrd-devtools checkout and
# the fixed shared-core candidate (xrdclient) must be supplied explicitly; the
# libraries are taken from xrdclient's siblings.
{ pkgs ? import <nixpkgs> { }, devtoolsSrc, xrdclientSrc }:
(import (devtoolsSrc + "/packaging/nix") {
  inherit pkgs xrdclientSrc;
  workspace = xrdclientSrc + "/..";
  xgfalclientSrc = ../.;
}).xgfalclient
