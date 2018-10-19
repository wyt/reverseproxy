package org.wangyt.reverseproxy.backup0830;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.apache.http.HttpConnection;
import org.apache.http.HttpHost;
import org.apache.http.impl.pool.BasicConnFactory;
import org.apache.http.impl.pool.BasicConnPool;
import org.apache.http.impl.pool.BasicPoolEntry;

public class HttpConnPool {

	public static final BasicConnPool INSTANCE = new BasicConnPool(new BasicConnFactory());

	static {
		INSTANCE.setDefaultMaxPerRoute(2);
		INSTANCE.setMaxTotal(10);
	}

	public static HttpConnection getConn(HttpHost httpHost, Object state) {
		HttpConnection conn = null;
		try {
			// 尝试从池中租用给定路由和给定状态的连接
			Future<BasicPoolEntry> future = INSTANCE.lease(httpHost, null);
			BasicPoolEntry entry = future.get();
			conn = entry.getConnection();
		} catch (InterruptedException | ExecutionException e) {
			e.printStackTrace();
		}
		return conn;
	}

	public static BasicPoolEntry getEntry(HttpHost httpHost, Object state) {                   
		BasicPoolEntry entry = null;
		try {
			// 尝试从池中租用给定路由和给定状态的连接
			Future<BasicPoolEntry> future = INSTANCE.lease(httpHost, null);
			entry = future.get();
		} catch (InterruptedException e) {
			e.printStackTrace();
		} catch (ExecutionException e) {
			e.printStackTrace();
		}
		return entry;
	}

	public static void release(BasicPoolEntry entry, boolean reusable) {
		if(entry != null) {
			INSTANCE.release(entry, reusable);
		}
	}

}
