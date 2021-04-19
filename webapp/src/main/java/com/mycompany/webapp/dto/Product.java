package com.mycompany.webapp.dto;

public class Product {
   private int pid;
   private String name;
   private String description;
   private String category;
   private int price;
   
   public int getPid() {
      return pid;
   }
   public void setPid(int pid) {
      this.pid = pid;
   }
   public String getName() {
      return name;
   }
   public void setName(String name) {
      this.name = name;
   }
   public String getDescription() {
      return description;
   }
   public void setDescription(String description) {
      this.description = description;
   }
   public String getCategory() {
      return category;
   }
   public void setCategory(String category) {
      this.category = category;
   }
   public int getPrice() {
      return price;
   }
   public void setPrice(int price) {
      this.price = price;
   }
}