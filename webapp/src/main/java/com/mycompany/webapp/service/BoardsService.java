package com.mycompany.webapp.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mycompany.webapp.dao.BoardsDao;
import com.mycompany.webapp.dto.Board;
import com.mycompany.webapp.dto.Pager;

@Service
public class BoardsService {
  
	@Autowired
	private BoardsDao boardsDao;
   
   public int insert(Board board) {
      return boardsDao.insert(board);
   }

   public int getCount() {
      return boardsDao.count();
   }

   public List<Board> getList(Pager pager) {
      return boardsDao.selectByPage(pager);
   }
   
   public Board getBoard(int bno) {
      return boardsDao.selectByBno(bno);
   }

   public int update(Board board) {
      return boardsDao.update(board);
   }

   public int delete(int bno) {
      return boardsDao.deleteByBno(bno);
   }
   
   public int addHitcount(int bno) {
      return boardsDao.updateBhitcount(bno);
   }
}