/*
 * Copyright 2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.example;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestOperations;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletResponse;

@RestController
final class Controller {

	@Value("${target.url:https://attendees.apps.gcp.borgescloud.com/}")
	private String targetUrl;

	static final String FORWARDED_URL = "X-CF-Forwarded-Url";
	static final String PROXY_METADATA = "X-CF-Proxy-Metadata";
	static final String PROXY_SIGNATURE = "X-CF-Proxy-Signature";

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	private final RestOperations restOperations;

	@Autowired
	Controller(RestOperations restOperations) {
		this.restOperations = restOperations;
	}

	@RequestMapping(headers = { FORWARDED_URL, PROXY_METADATA, PROXY_SIGNATURE })
	ResponseEntity<?> service(RequestEntity<byte[]> incoming) {
		this.logger.info(">>>>> # 1 # CF ROUTING: Incoming Request: {}", incoming);

		this.logger.info(">>>>> # 1 # CF ROUTING: FORWARDED_URL : " + incoming.getHeaders().get(FORWARDED_URL));
		this.logger.info(">>>>> # 1 # CF ROUTING: PROXY_METADATA: " + incoming.getHeaders().get(PROXY_METADATA));
		this.logger.info(">>>>> # 1 # CF ROUTING: PROXY_SIGNATURE: " + incoming.getHeaders().get(PROXY_SIGNATURE));

		RequestEntity<?> outgoing = getOutgoingRequest(incoming);
		this.logger.info("<<<<< # 1 # CF ROUTING: Outgoing Request: {}", outgoing);

		return this.restOperations.exchange(outgoing, byte[].class);
	}

	@RequestMapping(path = "/", headers = "!FORWARDED_URL")
	public ResponseEntity<?> index(RequestEntity<byte[]> incoming) throws URISyntaxException {
		this.logger.info(">>>>> # 2 # NO CF ROUTING SERVICE HEADERS: Incoming Request: {}", incoming);

		URI uri = new URI(targetUrl);

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (!(auth instanceof AnonymousAuthenticationToken)) {
			this.logger.info(">>>>> # 2 # Authenticated, should redirect");
			HttpHeaders headers = new HttpHeaders();
			headers.setLocation(uri);
			return new ResponseEntity<byte []>(null,headers,HttpStatus.FOUND);
		}

		RequestEntity<?> outgoing = new RequestEntity<>(incoming.getBody(), incoming.getHeaders(), incoming.getMethod(),
				uri);
		this.logger.info("<<<<< # 2 # NO CF ROUTING SERVICE HEADERS: Outgoing Request: {}", outgoing);

		return this.restOperations.exchange(outgoing, byte[].class);
	}

	// @RequestMapping(path = "/", headers = "location")
	//@RequestMapping(path = "/", headers = "!FORWARDED_URL")
	public void method(HttpServletResponse httpServletResponse) {
		this.logger.info("### NO CF ROUTING SERVICE HEADERS: Redirect");
		this.logger.info(">>>>> # 3 # NO CF ROUTING SERVICE HEADERS: Incoming Request: {}", httpServletResponse);

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (!(auth instanceof AnonymousAuthenticationToken)) {
			try {
				httpServletResponse.sendRedirect(targetUrl);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}

	private static RequestEntity<?> getOutgoingRequest(RequestEntity<?> incoming) {
		HttpHeaders headers = new HttpHeaders();
		headers.putAll(incoming.getHeaders());

		URI uri = headers.remove(FORWARDED_URL).stream().findFirst().map(URI::create)
				.orElseThrow(() -> new IllegalStateException(String.format("No %s header present", FORWARDED_URL)));

		return new RequestEntity<>(incoming.getBody(), headers, incoming.getMethod(), uri);
	}

}
