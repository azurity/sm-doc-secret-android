package net.imwork.a166q0w6939.ssltestndk;

public abstract class ServerCallback {
    public abstract void reqEnc(Server.Session s,Server server);

    public abstract void reqDec(Server.Session s,Server server);

    public abstract void finish(Server.Session s);
}
