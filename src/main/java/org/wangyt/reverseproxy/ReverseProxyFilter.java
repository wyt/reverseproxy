package org.wangyt.reverseproxy;

import java.beans.PropertyDescriptor;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.HttpCookie;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HeaderIterator;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.entity.StringEntity;
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
	public static final int TARGET_PORT = 8082;

	private HttpHost target;
	private HttpProcessor httpproc;

	/** 线程安全. */
	private static final HttpRequestExecutor HTTPEXECUTOR = new HttpRequestExecutor();

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		this.target = new HttpHost(TARGET_HOSTNAME, TARGET_PORT);
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

		/** 在反向代理服务器中写一个cookie */
		Cookie cookie = new Cookie("rptestcookie01", "nothing");
		cookie.setMaxAge(-1);
		cookie.setPath(request.getContextPath());
		cookie.setHttpOnly(true);
		response.addCookie(cookie);

		proxyHandle(request, response);
	}

	private void proxyHandle(HttpServletRequest request, HttpServletResponse response) {
		HttpCoreContext coreContext = HttpCoreContext.create();
		coreContext.setTargetHost(this.target);
		BasicPoolEntry entry = null;

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

			entry = HttpConnPool.getEntry(this.target, null);
			HttpResponse proxyResponse = HTTPEXECUTOR.execute(proxyRequest, entry.getConnection(), coreContext);
			HTTPEXECUTOR.postProcess(proxyResponse, httpproc, coreContext);
			respRefact(request, response, proxyResponse);
		} catch (HttpException e) {
			LOG.error(e.getMessage(), e);
		} catch (IOException e) {
			LOG.error(e.getMessage(), e);
		} finally {
			HttpConnPool.release(entry, false);
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

		HttpEntityEnclosingRequest proxyReq = new BasicHttpEntityEnclosingRequest(originalReq.getMethod(),
				genarateProxyRequestURI(originalReq));

		Enumeration<String> headerNames = originalReq.getHeaderNames();
		// 将Servlet请求处理成代理请求.
		while (headerNames.hasMoreElements()) {
			String key = (String) headerNames.nextElement();
			String value = originalReq.getHeader(key);
			LOG.info("original request headers >> " + key + ": " + value);
			if (key.equalsIgnoreCase(org.apache.http.cookie.SM.COOKIE)) {
				value = getRealCookie(value);
			}
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
	private void respRefact(HttpServletRequest originalRequest, HttpServletResponse originalResponse,
			HttpResponse proxyResponse) throws IOException {

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

			String headerName = header.getName();
			String headerValue = header.getValue();

			LOG.info("proxy response headers2 >> " + headerName + ": " + headerValue);
			if (headerName.equalsIgnoreCase(org.apache.http.cookie.SM.SET_COOKIE)
					|| headerName.equalsIgnoreCase(org.apache.http.cookie.SM.SET_COOKIE2)) {
				copyProxyCookie(originalRequest, originalResponse, headerValue);
			} else if (headerName.equalsIgnoreCase("Content-Type")) {
				originalResponse.setHeader("Content-type", headerValue);
			} else if (headerName.equalsIgnoreCase("Content-Length")) {
				originalResponse.setHeader("Content-Length", headerValue);
			} else {
				originalResponse.addHeader(headerName, headerValue);
			}
		}

		Collection<String> originalResponseHeaderNames2 = originalResponse.getHeaderNames();
		LOG.info("Content Type: " + originalResponse.getContentType() + ", Content Length: "
				+ originalResponse.getHeader("Content-Length"));

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

	protected void copyProxyCookie(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
			String headerValue) {

		List<HttpCookie> cookies = HttpCookie.parse(headerValue);

		for (HttpCookie cookie : cookies) {
			String proxyCookieName = "!Proxy!" + cookie.getName();
			Cookie servletCookie = new Cookie(proxyCookieName, cookie.getValue());
			servletCookie.setComment(cookie.getComment());
			servletCookie.setMaxAge((int) cookie.getMaxAge());
			servletCookie.setPath(cookie.getPath());
			servletCookie.setSecure(cookie.getSecure());
			servletCookie.setVersion(cookie.getVersion());
			servletCookie.setHttpOnly(cookie.isHttpOnly());

			try {
				PropertyDescriptor pd = new PropertyDescriptor("httpOnly", HttpCookie.class);
				Method getMethod = pd.getReadMethod();
				boolean isHttpOnly = (Boolean) getMethod.invoke(cookie, new Object[] {});
				LOG.info("isHttpOnly: " + isHttpOnly);
			} catch (Exception e) {
				LOG.error(e.getMessage(), e);
			}

			servletResponse.addCookie(servletCookie);
		}
	}

	/**
	 * 反向代理服务器不应该将自己本身写给浏览器的cookie,再发送到目标服务器中.
	 * 
	 * @param cookieValue
	 * @return
	 */
	protected String getRealCookie(String cookieValue) {
		StringBuilder escapedCookie = new StringBuilder();
		String cookies[] = cookieValue.split("[;,]");
		for (String cookie : cookies) {
			String cookieSplit[] = cookie.split("=");
			if (cookieSplit.length == 2) {
				String cookieName = cookieSplit[0].trim();
				if (cookieName.startsWith("!Proxy!")) {
					cookieName = cookieName.substring("!Proxy!".length());
					if (escapedCookie.length() > 0) {
						escapedCookie.append("; ");
					}
					escapedCookie.append(cookieName).append("=").append(cookieSplit[1].trim());
				}
			}
		}
		return escapedCookie.toString();
	}

	/**
	 * 截掉代理服务器contextPath.
	 * 
	 * @param request
	 * @return
	 */
	public static String genarateProxyRequestURI(HttpServletRequest request) {
		String qMark = "?";
		String incomingUrl = request.getRequestURI();
		String queryString = request.getQueryString();
		if (queryString == null) {
			queryString = "";
			qMark = "";
		}
		LOG.info("ProxyRequestURI >> " + incomingUrl + qMark + queryString);
		return incomingUrl + qMark + queryString;
	}

}
