package mambas.steganography;

import mambas.steganography.controller.ExtractController;
import mambas.steganography.controller.HideController;
import mambas.steganography.controller.PSNRController;
import mambas.steganography.model.SteganographyService;
import mambas.steganography.model.SteganographyServiceImpl;
import mambas.steganography.view.SteganographyView;
import mambas.steganography.view.SteganographyViewImpl;
import picocli.CommandLine;
import picocli.CommandLine.Command;

@Command(
        name = "stego-cli",
        mixinStandardHelpOptions = true,
        version = "Stego CLI 1.0",
        description = "CLI application for steganography on MP3 audio files."
)
public class App {
    public static void main(String[] args) {
        SteganographyService service = new SteganographyServiceImpl();
        SteganographyView view = new SteganographyViewImpl();

        HideController hideController = new HideController(service, view);
        ExtractController extractController = new ExtractController(service, view);
        PSNRController psnrController = new PSNRController(service, view);

        CommandLine cmd = new CommandLine(new App());
        cmd.addSubcommand("hide", hideController);
        cmd.addSubcommand("extract", extractController);
        cmd.addSubcommand("psnr", psnrController);

        int exitCode = cmd.execute(args);
        System.exit(exitCode);
    }
}
