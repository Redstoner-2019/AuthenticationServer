import me.redstoner2019.client.AuthenticatorClient;
import me.redstoner2019.server.AuthClientHandler;

import java.util.UUID;

public class Main {
    public static void main(String[] args) {
        //AuthenticatorClient client = new AuthenticatorClient("localhost",8009);
        AuthenticatorClient client = new AuthenticatorClient("158.220.105.209",8009);
        client.setup();
        System.out.println(client.tokeninfo("q9u5NDlgZ5qsBRNe97NuvDgGlQYCKkCQK6JMV/J9OedHLQ7m0wxaW12Reva2/dK3pLT4wa0miN0H8hgi3wYmOHX7Czokmc5K6996YLwaqN3cQFUDmRMw5bFi4owb1kTYg0v+xFJ38uSseSGVrWPDtL/TkI0v2wR1Cse1o65JWjw="));
    }
}
