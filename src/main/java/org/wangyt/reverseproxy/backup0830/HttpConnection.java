package org.wangyt.reverseproxy.backup0830;

import java.net.Socket;

import org.apache.http.HttpHost;
import org.apache.http.impl.DefaultBHttpClientConnection;

public class HttpConnection {
	
	DefaultBHttpClientConnection conn = new DefaultBHttpClientConnection(8 * 1024);
	
	public DefaultBHttpClientConnection getConn(HttpHost httpHost) {
		Socket socket = null;
		try {
			if (!conn.isOpen()) {
				socket = new Socket(httpHost.getHostName(), httpHost.getPort());
				conn.bind(socket);
			} 
		} catch (Exception e) {
			e.printStackTrace();
		}
		return conn;
	}
}
