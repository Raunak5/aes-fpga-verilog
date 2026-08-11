// =============================================================================
// AES-128 Encryption + Decryption  ─  Basys3 / Vivado 2025.x
// NIST FIPS-197 Appendix B test vector (fully verified)
//
// Test vector (NIST FIPS-197 Appendix B):
//   KEY:       2b7e151628aed2a6abf7158809cf4f3c
//   PLAINTEXT: 3243f6a8885a308d313198a2e0370734
//   CIPHERTEXT:3925841d02dc09fbdc118597196a0b32
//
// Bug-fix history vs original uploaded file
// ─────────────────────────────────────────
// B1  cipher/inv_cipher  ShiftRows/InvShiftRows byte indices were wrong.
//     Derived from first principles and verified against NIST intermediates.
//     ShiftRows  perm: [0,5,10,15, 4,9,14,3, 8,13,2,7,  12,1,6,11]
//     InvShiftRows perm:[0,13,10,7, 4,1,14,11, 8,5,2,15, 12,9,6,3]
//
// B2  cipher    AddRoundKey in step 5 used wrong round index (off-by-one).
//               Fixed: XOR state BEFORE incrementing round counter.
//
// B3  key_exp   round_keys packing read pending non-blocking writes for
//               rounds 0-9 → stale/X values.
//               Fixed: pack each key with blocking assignments immediately.
//
// B4  key_exp   done never cleared → second run ignored.
//               Fixed: return to idle and clear done after completion.
//
// B5  aes_top   SHOW_RESULT returned to IDLE same cycle done=1 →
//               testbench missed the pulse.
//               Fixed: hold done=1 for one full slow_clk cycle.
//
// B6  aes_top   start pulses not default-deasserted → spurious re-triggers.
//               Fixed: default-deassert all _start regs every cycle.
//
// B7  TESTBENCH WRONG TEST VECTOR (root cause of all FAIL outputs):
//               Original EXPECTED_CT 69c4e0d8...54b4 is the NIST C.1 result
//               for key=000102...0f, NOT for key 2b7e1516...
//               These two values came from different NIST appendices and
//               were mixed together - no correct AES can produce that CT
//               with that key.
//               Fixed: use the correct FIPS-197 Appendix B pairing.
//
// B8  File order: testbench was declared FIRST, crashing Vivado elaboration.
//               Fixed: all DUT modules precede the testbench.
// =============================================================================
 
`timescale 1ns / 1ps
 
// ============================================================================
// 1. Clock Divider  (divide-by-2)
// ============================================================================
module clock_divider(
    input  clk_in,
    input  rst_n,
    output reg slow_clk
);
    always @(posedge clk_in or negedge rst_n) begin
        if (~rst_n) slow_clk <= 1'b0;
        else        slow_clk <= ~slow_clk;
    end
endmodule