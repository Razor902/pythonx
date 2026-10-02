// ─────────────────────────────────────────────────────────────
// © 2026 Curtis Ray Dyess — PhantomX / Crimson Root. All rights reserved.
// Unauthorized copying, redistribution, automated collection, or
// model-training ingestion prohibited without prior written authorization.
// ─────────────────────────────────────────────────────────────
// xcu_tb.v -- testbench for xcu.v.
//
// Vectors are generated from the REAL C core by genvec.c (see run.sh):
//   vec/vec_cfg.vh        -> `define NUM_VECTORS <n>
//   vec/vec_<v>_len.txt   -> decimal byte count N
//   vec/vec_<v>_in.hex    -> N lines, one input byte each ("%02x")
//   vec/vec_<v>_exp.hex   -> 256*27 lines, expected counters ("%08x"),
//                            key-major: key k occupies lines k*27..k*27+26.
//
// For every vector the testbench resets the DUT, streams the input
// bytes, then reads back all 6912 counters through the read port and
// compares each against the C core's answer with !== (X catches X).

`timescale 1ns/1ps
`include "vec/vec_cfg.vh"

module xcu_tb;

  reg         clk = 0;
  reg         rst;
  reg         valid;
  reg  [7:0]  din;
  reg         last;
  wire        done;
  reg         rd_en;
  reg  [7:0]  rd_key;
  reg  [4:0]  rd_bin;
  wire [31:0] rd_data;
  wire        rd_valid;

  xcu dut (
    .clk(clk), .rst(rst),
    .valid(valid), .din(din), .last(last), .done(done),
    .rd_en(rd_en), .rd_key(rd_key), .rd_bin(rd_bin),
    .rd_data(rd_data), .rd_valid(rd_valid)
  );

  always #5 clk = ~clk;   // 100 MHz

  integer v, i, k, b, N, errors, vec_errors;
  integer flen, fin, fexp;
  reg [7:0]  byteval;
  reg [31:0] expval;
  reg [8*64:1] fname;

  task do_reset;
    begin
      rst = 1; valid = 0; last = 0; rd_en = 0;
      din = 0; rd_key = 0; rd_bin = 0;
      @(posedge clk); @(posedge clk); #1;
      rst = 0;
      @(posedge clk); #1;
    end
  endtask

  initial begin
    errors = 0;

    for (v = 0; v < `NUM_VECTORS; v = v + 1) begin
      vec_errors = 0;

      // ---- load vector length ----
      $sformat(fname, "vec/vec_%0d_len.txt", v);
      flen = $fopen(fname, "r");
      if (flen == 0) begin
        $display("FATAL: cannot open %0s", fname); $finish;
      end
      if ($fscanf(flen, "%d", N) != 1) begin
        $display("FATAL: bad len file %0s", fname); $finish;
      end
      $fclose(flen);

      // ---- stream the frame ----
      do_reset();
      if (N > 0) begin
        $sformat(fname, "vec/vec_%0d_in.hex", v);
        fin = $fopen(fname, "r");
        if (fin == 0) begin
          $display("FATAL: cannot open %0s", fname); $finish;
        end
        for (i = 0; i < N; i = i + 1) begin
          if ($fscanf(fin, "%h", byteval) != 1) begin
            $display("FATAL: short data file %0s at byte %0d", fname, i);
            $finish;
          end
          din   = byteval;
          valid = 1;
          last  = (i == N - 1);
          @(posedge clk); #1;
        end
        $fclose(fin);
        // done pulses during the cycle right after the last byte is counted
        // (it was registered at the final streaming edge above)
        if (!done) begin
          $display("FAIL vec %0d: done not asserted after %0d bytes", v, N);
          vec_errors = vec_errors + 1;
        end
        valid = 0; last = 0;
        @(posedge clk); #1;
      end

      // ---- read back all 256*27 counters, compare vs C ----
      $sformat(fname, "vec/vec_%0d_exp.hex", v);
      fexp = $fopen(fname, "r");
      if (fexp == 0) begin
        $display("FATAL: cannot open %0s", fname); $finish;
      end
      for (k = 0; k < 256; k = k + 1) begin
        for (b = 0; b < 27; b = b + 1) begin
          if ($fscanf(fexp, "%h", expval) != 1) begin
            $display("FATAL: short exp file %0s at k=%0d b=%0d", fname, k, b);
            $finish;
          end
          rd_en  = 1;
          rd_key = k;
          rd_bin = b;
          @(posedge clk); #1;   // rd_data/rd_valid registered: 1-cycle latency
          if (!rd_valid) begin
            $display("FAIL vec %0d: rd_valid low at k=%0d b=%0d", v, k, b);
            vec_errors = vec_errors + 1;
          end else if (rd_data !== expval) begin
            if (vec_errors < 8)
              $display("FAIL vec %0d: k=%0d bin=%0d rtl=%08h c=%08h",
                       v, k, b, rd_data, expval);
            vec_errors = vec_errors + 1;
          end
        end
      end
      $fclose(fexp);
      rd_en = 0;
      @(posedge clk); #1;

      if (vec_errors == 0)
        $display("PASS vec %0d (N=%0d bytes)", v, N);
      else
        $display("FAIL vec %0d (N=%0d): %0d mismatches", v, N, vec_errors);
      errors = errors + vec_errors;
    end

    $display("===================================");
    if (errors == 0)
      $display("ALL %0d VECTORS PASS: RTL == C core bit-for-bit", `NUM_VECTORS);
    else
      $display("FAILURES: %0d counter mismatches across vectors", errors);
    $display("===================================");
    $finish;
  end

  // Watchdog: longest vector is a few thousand bytes; readout is
  // 6912 cycles per vector. 100 ms of sim time is far beyond need.
  initial begin
    #100000000;
    $display("FATAL: simulation watchdog timeout");
    $finish;
  end

endmodule
