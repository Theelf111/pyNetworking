{
  python313,
}: let
  python = python313;
  pythonPkgs = python.pkgs;
  inherit (pythonPkgs) buildPythonPackage rsa cryptography;
in
  buildPythonPackage (final: {
    pname = "py-networking";
    version = "0.1";

    src = ./.;

    propagatedBuildInputs = [
      python.pkgs.setuptools
    ];

    dependencies = [
      rsa
      cryptography
    ];

    pyproject = true;
  })
