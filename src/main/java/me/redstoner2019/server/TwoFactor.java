package me.redstoner2019.server;

public class TwoFactor {
    private String username;
    private String code;
    private long expires;

    public TwoFactor(String username, String code, long expires) {
        this.username = username;
        this.code = code;
        this.expires = expires;
    }

    public long getExpires() {
        return expires;
    }

    public void setExpires(long expires) {
        this.expires = expires;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
