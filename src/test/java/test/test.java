package test;

import com.zyc.NmapScan;

public class test {
    public static void main(String[] args) {
        System.out.println(NmapScan.scanNorm("127.0.0.1",null,"-T4 -A -v"));
    }
}
