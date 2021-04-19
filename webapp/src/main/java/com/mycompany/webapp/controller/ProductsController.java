package com.mycompany.webapp.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.mycompany.webapp.dto.Pager;
import com.mycompany.webapp.dto.Product;
import com.mycompany.webapp.service.ProductsService;

@RestController
@RequestMapping("/products")
class ProductsController {
	private final Logger logger = LoggerFactory.getLogger(ProductsController.class);

	@Autowired
	private ProductsService productsService;

	@GetMapping("")
	public Map<String, Object> list(@RequestParam(defaultValue = "1") int pageNo) {
		int totalRows = productsService.getCount();
		Pager pager = new Pager(5, 5, totalRows, pageNo);
		List<Product> list = productsService.getList(pager);
		Map<String, Object> map = new HashMap<>();
		map.put("pager", pager);
		map.put("products", list);

		return map; // JSON을 만들기 위한 데이터가 리턴된다.
		// @RestController 어노테이션이 설정되어 있어서 리턴값이 JSON으로 자동으로 컨버팅된다.
	}

	@GetMapping("/{pid}")
	public Product read(@PathVariable int pid) {
		Product product = productsService.getProduct(pid);
		return product;
	}

	@PostMapping("")
	//@RequestBody : 요청 HTTP 본문에 JSON이 포함되어 있을 경우 
	public Product create(@RequestBody Product product) {
		productsService.insert(product);
		return product;
	}

	@PutMapping("")
	public Product update(@RequestBody Product product) {
		productsService.update(product);
		return product;
	}

	@DeleteMapping("/{pid}")
	public void delete(@PathVariable int pid) {
		productsService.delete(pid);
	}

}
