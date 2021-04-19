package com.mycompany.webapp.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mycompany.webapp.dao.ProductsDao;
import com.mycompany.webapp.dto.Pager;
import com.mycompany.webapp.dto.Product;

@Service
public class ProductsService {
   @Autowired
   private ProductsDao productsDao;
   
   public List<Product> getList(Pager pager) {
      return productsDao.selectByPage(pager);
   }
   
   public int getCount() {
	   return productsDao.count();
   }
   
   public Product getProduct(int pid) {
      return productsDao.selectByPid(pid);
   }
   
   public int insert(Product product) {
      return productsDao.insert(product);
   }
   
   public int delete(int pid) {
      return productsDao.deleteByPid(pid);
   }
   
   public int update(Product product) {
      return productsDao.update(product);
   }
}