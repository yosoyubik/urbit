{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    tools = {
      flake = false;
      url = "github:urbit/tools/d454e2482c3d4820d37db6d5625a6d40db975864";
    };
  };

  outputs = { self, nixpkgs, flake-utils, tools }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        usableTools = pkgs.runCommand "patched-tools" { } ''
          cp -r ${tools} $out
          chmod +w -R $out
          patchShebangs $out
        '';
        # Wrap click to use GNU tools (needed for macOS compatibility)
        wrappedClick = pkgs.writeShellScriptBin "click" ''
          export PATH="${pkgs.netcat-gnu}/bin:${pkgs.gnused}/bin:${pkgs.coreutils}/bin:$PATH"
          exec ${usableTools}/pkg/click/click "$@"
        '';
        bootFakeShip = { pill, arvo }:
          pkgs.runCommand "fake-pier" { } ''
            ${./urbit} --pier $out -F zod -B ${pill} -l -x -t -A ${arvo}
          '';
        fakePier = bootFakeShip {
          pill = ./bin/solid.pill;
          arvo = "${./pkg}/arvo";
        };
        testPier = bootFakeShip {
          pill = ./bin/solid.pill;
          arvo = pkgs.runCommand "test-arvo" {} ''
            cp -r ${./pkg} $out
            chmod +w -R $out
            cp -r ${./tests} $out/arvo/tests
            cp -r ${./test-desk.bill} $out/arvo/desk.bill
          '' + "/arvo";
        };
        buildPillThread = pill:
          pkgs.writeTextFile {
            name = "";
            text = ''
              =/  m  (strand ,vase)
              ;<  [=ship =desk =case]  bind:m  get-beak
              ;<  ~  bind:m  (poke [ship %dojo] %lens-command !>([%$ [%dojo '+${pill}'] [%output-pill '${pill}/pill']]))
              ;<  ~  bind:m  (poke [ship %hood] %drum-exit !>(~))
              (pure:m !>(~))
            '';
          };
        buildPill = pill:
          pkgs.runCommand ("${pill}.pill") { buildInputs = [ pkgs.netcat-gnu ]; } ''
            cp -r ${fakePier} pier
            chmod +w -R pier
            ${./urbit} -d pier
            ${wrappedClick}/bin/click -k -p -i ${buildPillThread pill} pier

            # Sleep to let urbit spin down properly
            sleep 5

            cp pier/.urb/put/${pill}.pill $out
          '';

      in {
        checks = {
          testFakeShip = import ./nix/test-fake-ship.nix {
            inherit pkgs;
            pier = testPier;
            click = "${wrappedClick}/bin/click";
          };
          testAqua = import ./nix/test-aqua.nix {
            inherit pkgs;
            pier = fakePier;
            click = "${wrappedClick}/bin/click";
          };
        };
        packages = {
          inherit fakePier testPier;
          brass = buildPill "brass";
          ivory = buildPill "ivory";
          solid = buildPill "solid";
        };
      });
}
