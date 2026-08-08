package io.huntwarden.probe;

import com.sun.tools.attach.VirtualMachine;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

public final class Main {
    private Main() {}

    public static void main(String[] args) throws Exception {
        if (args.length < 3 || !"attach".equals(args[0])) {
            System.err.println("usage: java -jar probe.jar attach <pid> <list_components|inspect_class|dump_class> [className]");
            System.exit(2);
        }
        String pid = args[1];
        String command = args[2];
        String className = args.length > 3 ? args[3] : "";
        if (!command.matches("list_components|inspect_class|dump_class")) throw new IllegalArgumentException("invalid command");
        if (!className.isEmpty() && !className.matches("[A-Za-z_$][A-Za-z0-9_$.]{0,511}")) throw new IllegalArgumentException("invalid class name");

        Path output = Files.createTempFile("huntwarden-probe-", ".json");
        Files.deleteIfExists(output);
        String request = String.join("\n", command, className, output.toAbsolutePath().toString());
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(request.getBytes(StandardCharsets.UTF_8));
        Path ownJar = Path.of(new URI(Main.class.getProtectionDomain().getCodeSource().getLocation().toString()));

        VirtualMachine machine = VirtualMachine.attach(pid);
        try {
            machine.loadAgent(ownJar.toString(), encoded);
        } finally {
            machine.detach();
        }

        Instant deadline = Instant.now().plus(Duration.ofSeconds(20));
        while (!Files.exists(output) && Instant.now().isBefore(deadline)) Thread.sleep(50);
        if (!Files.exists(output)) throw new IllegalStateException("probe response timeout");
        try {
            System.out.print(Files.readString(output, StandardCharsets.UTF_8));
        } finally {
            Files.deleteIfExists(output);
        }
    }
}
