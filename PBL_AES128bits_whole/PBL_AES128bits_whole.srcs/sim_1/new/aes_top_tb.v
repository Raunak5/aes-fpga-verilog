// ============================================================================
// 8. Testbench  (LAST - Vivado elaborates top-down)
// ============================================================================
`timescale 1ns / 1ps
module aes_top_tb;
 
    reg          clk_100mhz, rst_n, start;
    wire [7:0]   led;
    wire         done, slow_clk, enc_done, dec_done;
    wire [127:0] dbg_key, dbg_plaintext, dbg_ciphertext, dbg_decrypted;
    wire [2:0]   dbg_state;
 
    // FIPS-197 Appendix B - the only correct pairing for key 2b7e1516...
    localparam [127:0] EXPECTED_CT = 128'h3925841d02dc09fbdc118597196a0b32;
    localparam [127:0] EXPECTED_PT = 128'h3243f6a8885a308d313198a2e0370734;
 
    aes_top uut (
        .clk_100mhz(clk_100mhz),.rst_n(rst_n),.start(start),
        .led(led),.done(done),.dbg_key(dbg_key),.dbg_plaintext(dbg_plaintext),
        .dbg_ciphertext(dbg_ciphertext),.dbg_decrypted(dbg_decrypted),
        .slow_clk(slow_clk),.dbg_state(dbg_state),.enc_done(enc_done),.dec_done(dec_done));
 
    initial clk_100mhz=0;
    always #5 clk_100mhz=~clk_100mhz;
 
    integer pass_count, fail_count;
    reg done_seen;
 
    initial begin done_seen=0; #2_000_000;
        if(!done_seen) begin $display("TIMEOUT"); $finish; end end
 
    reg [2:0] prev_state; reg prev_done;
    initial begin prev_state=0; prev_done=0; end
    always @(posedge clk_100mhz)
        if(dbg_state!==prev_state||done!==prev_done) begin
            $display("[%0t ns] state=%0d enc=%b dec=%b done=%b",
                $time,dbg_state,enc_done,dec_done,done);
            prev_state<=dbg_state; prev_done<=done; end
 
    task pulse_start;
        begin @(negedge clk_100mhz); start=1; #200; @(negedge clk_100mhz); start=0; end
    endtask
 
    initial begin
        pass_count=0; fail_count=0; rst_n=0; start=0;
        $display("==========================================");
        $display("  AES-128  FIPS-197 Appendix B");
        $display("  KEY: 2b7e151628aed2a6abf7158809cf4f3c");
        $display("  PT:  3243f6a8885a308d313198a2e0370734");
        $display("  EXP: 3925841d02dc09fbdc118597196a0b32");
        $display("==========================================");
 
        repeat(10) @(posedge clk_100mhz);
        @(negedge clk_100mhz); rst_n=1;
        $display("[%0t ns] Reset released.", $time);
        repeat(20) @(posedge clk_100mhz);
 
        // ── Run 1 ────────────────────────────────
        pulse_start;
        wait(done===1'b1); done_seen=1;
        $display("[%0t ns] done asserted.", $time);
        repeat(4) @(posedge clk_100mhz);
 
        $display("\n--- TEST 1: Ciphertext ---");
        $display("Got:  %h", dbg_ciphertext);
        $display("Exp:  %h", EXPECTED_CT);
        if(dbg_ciphertext===EXPECTED_CT) begin $display("PASS"); pass_count=pass_count+1; end
        else begin $display("FAIL"); fail_count=fail_count+1; end
 
        $display("\n--- TEST 2: Decryption round-trip ---");
        $display("Got:  %h", dbg_decrypted);
        $display("Exp:  %h", EXPECTED_PT);
        if(dbg_decrypted===EXPECTED_PT) begin $display("PASS"); pass_count=pass_count+1; end
        else begin $display("FAIL"); fail_count=fail_count+1; end
 
        $display("\n--- TEST 3: LED ---");
        $display("LED: %h  Exp: %h", led, EXPECTED_PT[127:120]);
        if(led===EXPECTED_PT[127:120]) begin $display("PASS"); pass_count=pass_count+1; end
        else begin $display("FAIL"); fail_count=fail_count+1; end
 
        // ── Run 2 re-trigger ─────────────────────
        $display("\n--- TEST 4: Re-trigger ---");
        wait(dbg_state===3'd0); repeat(10) @(posedge clk_100mhz);
        done_seen=0; pulse_start;
        wait(done===1'b1); done_seen=1;
        repeat(4) @(posedge clk_100mhz);
        if(dbg_ciphertext===EXPECTED_CT && dbg_decrypted===EXPECTED_PT) begin
            $display("PASS"); pass_count=pass_count+1; end
        else begin $display("FAIL"); fail_count=fail_count+1; end
 
        $display("\n==========================================");
        $display("  PASSED %0d / %0d", pass_count, pass_count+fail_count);
        if(fail_count==0) $display("  ALL TESTS PASSED");
        else              $display("  SOME TESTS FAILED");
        $display("==========================================");
        #500; $finish;
    end
endmodule