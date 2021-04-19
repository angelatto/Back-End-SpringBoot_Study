package com.mycompany.webapp.dao;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

import com.mycompany.webapp.dto.Pager;
import com.mycompany.webapp.dto.Product;

@Mapper
public interface ProductsDao {
   public List<Product> selectByPage(Pager pager);
   public int count();
   public Product selectByPid(int pid);
   public int insert(Product product);
   public int deleteByPid(int pid);
   public int update(Product product);
}