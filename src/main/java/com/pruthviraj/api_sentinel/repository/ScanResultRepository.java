package com.pruthviraj.api_sentinel.repository;

import com.pruthviraj.api_sentinel.model.ScanResult;
import com.pruthviraj.api_sentinel.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanResultRepository
        extends JpaRepository<ScanResult, Long> {

    List<ScanResult> findAllByUserOrderByScannedAtDesc(User user);
}