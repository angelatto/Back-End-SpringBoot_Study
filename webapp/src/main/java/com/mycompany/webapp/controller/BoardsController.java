package com.mycompany.webapp.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.mycompany.webapp.dto.Board;
import com.mycompany.webapp.dto.Pager;
import com.mycompany.webapp.service.BoardsService;

@RestController
@RequestMapping("/boards")
public class BoardsController {
	private final Logger logger = LoggerFactory.getLogger(BoardsController.class);

	@Autowired
	private BoardsService boardsService;

	@GetMapping("")
	public Map<String, Object> list(@RequestParam(defaultValue = "1") int pageNo) {
		int totalRows = boardsService.getCount();
		Pager pager = new Pager(5, 5, totalRows, pageNo);
		List<Board> list = boardsService.getList(pager);
		Map<String, Object> map = new HashMap<>();
		map.put("pager", pager);
		map.put("boards", list);

		return map; // JSON을 만들기 위한 데이터가 리턴된다.
		// @RestController 어노테이션이 설정되어 있어서 리턴값이 JSON으로 자동으로 컨버팅된다.
	}

	@PostMapping("")
	public void create(Board board) {
		logger.info(board.getBtitle());
		logger.info(board.getBcontent());
		logger.info(board.getBwriter());
		logger.info(board.getBattachoname());
		logger.info(board.getBattachsname());
		logger.info(board.getBattachtype());
		if (board.getBattach() != null && !board.getBattach().isEmpty()) {
			MultipartFile mf = board.getBattach();
			board.setBattachoname(mf.getOriginalFilename());
			board.setBattachsname(new Date().getTime() + "-" + mf.getOriginalFilename());
			board.setBattachtype(mf.getContentType());
			try {
				File file = new File("/Users/homecj/Pictures/uploadfiles/" + board.getBattachsname());
				mf.transferTo(file);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		boardsService.insert(board);
	}

	@GetMapping("/{bno}")
	public Board read(@PathVariable int bno) {
		boardsService.addHitcount(bno); // 조회수 1 증가
		Board board = boardsService.getBoard(bno);
		return board;
	}

	@GetMapping("/battach/{bno}")
	public void download(@PathVariable int bno, HttpServletResponse response) {
		try {
			Board board = boardsService.getBoard(bno);
			String battachoname = board.getBattachoname();
			if (battachoname == null)
				return;
			battachoname = new String(battachoname.getBytes("UTF-8"), "ISO-8859-1");
			String battachsname = board.getBattachsname();
			String battachspath = "/Users/homecj/Pictures/uploadfiles/" + battachsname;
			String battachtype = board.getBattachtype();

			response.setHeader("Content-Disposition", "attachment; filename=\"" + battachoname + "\";");
			response.setContentType(battachtype);

			InputStream is = new FileInputStream(battachspath);
			OutputStream os = response.getOutputStream();
			FileCopyUtils.copy(is, os);
			is.close();
			os.flush();
			os.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
