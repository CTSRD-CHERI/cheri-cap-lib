{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let # helper bindings
        # imported nix packages
        pkgs = import nixpkgs { inherit system; };
        # shell environment
        dfltShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            sby
            boolector
            haskellPackages.sv2v
            bluespec
          ];
        };
      # output attribute set
      in {
        devShells.default = dfltShell;
      }
    );
}
