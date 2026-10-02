// ─────────────────────────────────────────────────────────────
// © 2026 Curtis Ray Dyess — PhantomX / Crimson Root. All rights reserved.
// Unauthorized copying, redistribution, automated collection, or
// model-training ingestion prohibited without prior written authorization.
// ─────────────────────────────────────────────────────────────
// xcu.v -- XCU: XOR count array.
//
// First silicon block of the PythonX processor (see
// ../px-processor-sketch.md, stage 2). Bit-for-bit model of the C
// function px_xor_all_counts() in ../../fastcore.c:
//
//   for key k = 0..255, for each input byte s[i]:
//       c = s[i] ^ k
//       'a'..'z' -> bin c-'a'          (bins 0..25)
//       'A'..'Z' -> bin c-'A'          (bins 0..25)
//       0x20     -> bin 26
//       anything else is ignored
//
// 256 lanes run in parallel; one input byte per clock is broadcast to
// every lane, each lane XORs with its own key (the lane index) and
// increments at most one of its 27 counters. Counters are CNT_W bits,
// matching C's 32-bit int.
//
// Interface is a simple streaming frame protocol:
//   - rst (synchronous) clears all counters and drops done.
//   - valid+din present one frame byte per cycle; last marks the final
//     byte. done pulses for one cycle when the frame is fully counted.
//   - counters are read back through rd_en/rd_key/rd_bin -> rd_data
//     (one-cycle latency, rd_valid follows rd_en).
//
// Synthesizable Verilog-2001. No testbench constructs in this file.

module xcu #(
  parameter N_KEYS = 256,   // XOR keys 0..255, one lane each
  parameter N_BINS = 27,    // 26 letters (case-insensitive) + space
  parameter CNT_W  = 32    // counter width; matches C int
)(
  input  wire             clk,
  input  wire             rst,
  input  wire             valid,
  input  wire [7:0]      din,
  input  wire             last,
  output reg              done,
  input  wire             rd_en,
  input  wire [7:0]       rd_key,
  input  wire [4:0]       rd_bin,
  output reg [CNT_W-1:0] rd_data,
  output reg              rd_valid
);

  // One read-data wire per lane; the top-level key mux picks one.
  wire [CNT_W-1:0] lane_out [0:N_KEYS-1];

  genvar k;
  generate
    for (k = 0; k < N_KEYS; k = k + 1) begin : lane
      localparam [7:0] KEY = k;   // this lane's XOR key

      reg [CNT_W-1:0] cnt [0:N_BINS-1];

      // The C expression: c = (unsigned char)(s[i] ^ k)
      wire [7:0] x = din ^ KEY;

      // Bin decode, exactly the C if/else chain:
      //   'a'..'z' -> c-'a', 'A'..'Z' -> c-'A', 0x20 -> 26.
      wire is_lo = (x >= 8'h61) && (x <= 8'h7A);
      wire is_hi = (x >= 8'h41) && (x <= 8'h5A);
      wire is_sp = (x == 8'h20);
      wire hit   = valid & (is_lo | is_hi | is_sp);
      wire [4:0] bin = is_lo ? (x - 8'h61)
                     : is_hi ? (x - 8'h41)
                     : 5'd26;

      integer b;
      always @(posedge clk) begin
        if (rst) begin
          for (b = 0; b < N_BINS; b = b + 1)
            cnt[b] <= {CNT_W{1'b0}};
        end else if (hit) begin
          cnt[bin] <= cnt[bin] + 1'b1;
        end
      end

      // Per-lane bin mux for the read port (27:1).
      reg [CNT_W-1:0] bin_mux;
      always @(*) bin_mux = cnt[rd_bin];

      assign lane_out[k] = bin_mux;
    end
  endgenerate

  // Top-level key mux (256:1) with registered read port.
  always @(posedge clk) begin
    if (rst) begin
      done     <= 1'b0;
      rd_valid <= 1'b0;
      rd_data  <= {CNT_W{1'b0}};
    end else begin
      done     <= valid & last;
      rd_valid <= rd_en;
      if (rd_en)
        rd_data <= lane_out[rd_key];
    end
  end

endmodule
