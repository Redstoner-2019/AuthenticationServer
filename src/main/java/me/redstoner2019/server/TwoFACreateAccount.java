package me.redstoner2019.server;

public class TwoFACreateAccount extends TwoFactor{
    private String displayname;
    private String email;
    private String password;

    public TwoFACreateAccount(String username, String code, long expires, String displayname, String email, String password) {
        super(username, code, expires);
        this.displayname = displayname;
        this.email = email;
        this.password = password;
    }

    public String getDisplayname() {
        return displayname;
    }

    public void setDisplayname(String displayname) {
        this.displayname = displayname;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
