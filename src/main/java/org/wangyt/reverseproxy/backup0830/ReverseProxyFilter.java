package org.wangyt.reverseproxy.backup0830;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Enumeration;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.ConnectionReuseStrategy;
import org.apache.http.Header;
import org.apache.http.HeaderIterator;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.DefaultConnectionReuseStrategy;
import org.apache.http.impl.pool.BasicPoolEntry;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpProcessorBuilder;
import org.apache.http.protocol.HttpRequestExecutor;
import org.apache.http.protocol.RequestConnControl;
import org.apache.http.protocol.RequestContent;
import org.apache.http.protocol.RequestExpectContinue;
import org.apache.http.protocol.RequestTargetHost;
import org.apache.http.protocol.RequestUserAgent;

/**
 * http://localhost/proxy
 * 
 * @author WANG YONG TAO
 *
 */
@SuppressWarnings("all")
public class ReverseProxyFilter implements Filter {

	private static final Log LOG = LogFactory.getLog(ReverseProxyFilter.class);

	public static final String TARGET_HOSTNAME = "192.168.9.30";
	public static final int TARGET_PORT = 8185;

	private HttpHost target;
	private BasicPoolEntry entry;
	private HttpProcessor httpproc;

	/** 线程安全. */
	private static final HttpRequestExecutor HTTPEXECUTOR = new HttpRequestExecutor();

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		this.target = new HttpHost(TARGET_HOSTNAME, TARGET_PORT);
		// this.entry = HttpConnPool.getEntry(this.target, null);
		this.httpproc = HttpProcessorBuilder.create() //
				.add(new RequestContent()) //
				.add(new RequestTargetHost()) //
				.add(new RequestConnControl()) //
				.add(new RequestUserAgent("WINC REVERSE PROXY/1.1")) //
				.add(new RequestExpectContinue(true)) //
				.build();
	}

	@Override
	public void destroy() {

	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		proxyHandle(request, response);
	}

	private void proxyHandle(HttpServletRequest request, HttpServletResponse response) {

		ConnectionReuseStrategy connStrategy = DefaultConnectionReuseStrategy.INSTANCE;
		HttpCoreContext coreContext = HttpCoreContext.create();
		coreContext.setTargetHost(this.target);
		boolean reusable = false;

		try {
			HttpEntityEnclosingRequest proxyRequest = reqRefact(request);

			HTTPEXECUTOR.preProcess(proxyRequest, httpproc, coreContext);
			LOG.info("request line: " + proxyRequest.getRequestLine());

			/** 打印代理请求头 */
			HeaderIterator it = proxyRequest.headerIterator();
			while (it.hasNext()) {
				LOG.info("proxy request header >> " + it.next());
			}
			System.out.println("------------------------------");

			// HttpResponse proxyResponse = HTTPEXECUTOR.execute(proxyRequest,
			// entry.getConnection(), coreContext);
			HttpResponse proxyResponse = HTTPEXECUTOR.execute(proxyRequest, new HttpConnection().getConn(target),
					coreContext);
			HTTPEXECUTOR.postProcess(proxyResponse, httpproc, coreContext);
			respRefact(response, proxyResponse);
			reusable = connStrategy.keepAlive(proxyResponse, coreContext);
		} catch (HttpException e) {
			LOG.error(e.getMessage(), e);
		} catch (IOException e) {
			LOG.error(e.getMessage(), e);
		} finally {
			if (reusable) {
				LOG.info("Connection kept alive...");
			}
			HttpConnPool.release(entry, reusable);
		}
	}

	/**
	 * 重构HttpServletRequest.
	 * 
	 * @param originalReq
	 * @return
	 * @throws IOException
	 */
	private HttpEntityEnclosingRequest reqRefact(HttpServletRequest originalReq) throws IOException {

		// HttpEntityEnclosingRequest proxyReq = new
		// BasicHttpEntityEnclosingRequest(originalReq.getMethod(),
		// originalReq.getRequestURI());
		HttpEntityEnclosingRequest proxyReq = new BasicHttpEntityEnclosingRequest(originalReq.getMethod(),
				"/sfa_sp/login.jsp");

		Enumeration<String> headerNames = originalReq.getHeaderNames();

		// 将Servlet请求处理成代理请求.
		while (headerNames.hasMoreElements()) {
			String key = (String) headerNames.nextElement();
			String value = originalReq.getHeader(key);
			LOG.info("original request headers >> " + key + ": " + value);
			proxyReq.addHeader(key, value);
		}

		// Remove hop-by-hop headers.
		proxyReq.removeHeaders(HTTP.CONTENT_LEN);
		proxyReq.removeHeaders(HTTP.TRANSFER_ENCODING);
		proxyReq.removeHeaders(HTTP.CONN_DIRECTIVE);
		proxyReq.removeHeaders("Keep-Alive");
		proxyReq.removeHeaders("Proxy-Authenticate");
		proxyReq.removeHeaders("TE");
		proxyReq.removeHeaders("Trailers");
		proxyReq.removeHeaders("Upgrade");
		proxyReq.setHeader("Host", target.getHostName() + ":" + target.getPort());
		proxyReq.setEntity(new InputStreamEntity(originalReq.getInputStream(), getContentLength(originalReq)));
		return proxyReq;
	}

	/**
	 * 重构 ServletResponse.
	 * 
	 * @param servletResponse
	 * @param proxyResponse
	 * @throws IOException
	 */
	private void respRefact(ServletResponse servletResponse, HttpResponse proxyResponse) throws IOException {

		HttpServletResponse originalResponse = (HttpServletResponse) servletResponse;
		Collection<String> originalResponseHeaderNames = originalResponse.getHeaderNames();

		LOG.info("Content Type: " + originalResponse.getContentType());
		/** 打印原始响应头 */
		for (String key : originalResponseHeaderNames) {
			LOG.info("original response headers >> " + key + ": " + originalResponse.getHeader(key));
		}

		/** 打印代理响应头 */
		HeaderIterator it = proxyResponse.headerIterator();
		while (it.hasNext()) {
			LOG.info("proxy response headers >> " + it.next());
		}

		/** 代理请求头拷贝到原始响应头 */
		for (Header header : proxyResponse.getAllHeaders()) {
			LOG.info("proxy response headers2 >> " + header.getName() + ": " + header.getValue());
			originalResponse.addHeader(header.getName(), header.getValue());

			Header[] contentTypeHeader = proxyResponse.getHeaders("Content-Type");
			for (Header h : contentTypeHeader) {
				originalResponse.setContentType(h.getValue());
			}

			Header[] contentTypeLength = proxyResponse.getHeaders("Content-Length");
			for (Header h : contentTypeLength) {
				originalResponse.setContentLength(Integer.parseInt(h.getValue()));
			}
		}

		Collection<String> originalResponseHeaderNames2 = originalResponse.getHeaderNames();
		LOG.info("Content Type: " + originalResponse.getContentType());

		/** 打印修改后的原始响应头 */
		for (String key : originalResponseHeaderNames2) {
			LOG.info("original response headers2 >> " + key + ": " + originalResponse.getHeader(key));
		}

		HttpEntity entity = proxyResponse.getEntity();
		if (entity != null) {
			OutputStream servletOutputStream = originalResponse.getOutputStream();
			entity.writeTo(servletOutputStream);
		}
	}

	private long getContentLength(HttpServletRequest request) {
		String contentLengthHeader = request.getHeader("Content-Length");
		if (contentLengthHeader != null) {
			return Long.parseLong(contentLengthHeader);
		}
		return -1L;
	}

}
