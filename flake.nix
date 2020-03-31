
{
  description = "Nim Scuttlebutt development flake";

  edition = 201909;

  outputs = { self, nixpkgs, nimble }: {

    devShell.x86_64-linux = nixpkgs.legacyPackages.x86_64-linux.mkShell {
      name = "scuttlebutt";
      buildInputs = (with nimble.packages.x86_64-linux; [ nim nimble ])
        ++ (with nixpkgs.legacyPackages.x86_64-linux; [ libsodium ]);
    };

  };
}
