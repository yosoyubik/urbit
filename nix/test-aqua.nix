{ click, pier, pkgs }:

pkgs.stdenvNoCC.mkDerivation {
  name = "test-aqua";

  src = pier;

  phases = [ "unpackPhase" "buildPhase" "checkPhase" ];

  nativeBuildInputs = [ pkgs.netcat-openbsd pkgs.gnused pkgs.coreutils ];

  unpackPhase = ''
    cp -R $src ./pier
    chmod -R u+rw ./pier
  '';

  buildPhase = ''
    set -x
    set -e

    ${../urbit} -d ./pier 1>&2 2> $out

    tail -F $out >&2 &
    TAIL_PID=$!

    # Wait for ship to boot
    sleep 15

    # Start aqua app
    echo "Starting aqua app..."
    ${click} -c ./pier '|start %aqua'

    sleep 5

    # Load brass pill into aqua
    echo "Loading brass pill..."
    ${click} -c ./pier ':aqua +pill/brass'

    sleep 10

    # Run ph-all integration tests
    echo "Running ph-all tests..."
    ${click} -c ./pier '-ph-all'

    # Wait for tests to complete (ph-all runs multiple tests)
    sleep 300

    # Stop tailing logs
    kill $TAIL_PID 2>/dev/null || true

    # Exit gracefully
    ${click} -c ./pier '|exit'

    sleep 10

    set +x
  '';

  checkPhase = ''
    echo "Checking aqua test results..."

    # Check for test failures
    if egrep "ph-all:.*failed:" $out >/dev/null; then
      echo "ERROR: Aqua tests failed"
      exit 1
    fi

    # Check for crashes
    if egrep "(CRASHED|bail:)" $out >/dev/null; then
      echo "ERROR: Aqua tests crashed"
      exit 1
    fi

    # Check that tests completed
    if ! egrep "ph-all: %ph-.*complete" $out >/dev/null; then
      echo "ERROR: No aqua tests completed"
      exit 1
    fi

    echo "Aqua tests passed!"
  '';

  doCheck = true;

  # Fix 'bind: operation not permitted' when nix.useSandbox = true on darwin.
  __darwinAllowLocalNetworking = true;
}
