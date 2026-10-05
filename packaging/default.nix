# The fixed shared-core candidate must be supplied explicitly.
{ pkgs ? import <nixpkgs> { }, xrdclientSrc }:
(import (xrdclientSrc + "/packaging/nix") {
  inherit pkgs xrdclientSrc;
  xgfalclientSrc = ../.;
}).xgfalclient
