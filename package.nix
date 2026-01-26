{
  python313,
}: let
  python = python313;
  pythonPkgs = python.pkgs;
  inherit (pythonPkgs) buildPythonPackage;
in
  buildPythonPackage (final: {
    pname = "py-networking";
    version = "0.1";

    src = ./.;

    propagatedBuildInputs = [
      python.pkgs.setuptools
    ];

    pyproject = true;
  })
