// ============================================================================
// 7. AES Top  (Basys3)
// ============================================================================
module aes_top(
    input        clk_100mhz,
    input        rst_n,
    input        start,
    output reg [7:0] led,
    output reg   done,
    output [127:0] dbg_key,
    output [127:0] dbg_plaintext,
    output [127:0] dbg_ciphertext,
    output [127:0] dbg_decrypted,
    output wire  slow_clk,
    output wire [2:0] dbg_state,
    output wire  enc_done,
    output wire  dec_done
);
    clock_divider u_clkdiv (.clk_in(clk_100mhz),.rst_n(rst_n),.slow_clk(slow_clk));
 
    // FIPS-197 Appendix B test vector
    localparam [127:0] TEST_KEY = 128'h2b7e151628aed2a6abf7158809cf4f3a;
    localparam [127:0] TEST_PT = 128'h4D697477707500000000000000000000;
 
    reg          key_exp_start, enc_start, dec_start;
    wire         key_exp_done;
    wire [1407:0] round_keys;
    wire [127:0] ciphertext, decrypted;
 
    key_expansion u_kex (.clk(slow_clk),.rst_n(rst_n),.start(key_exp_start),
        .key_in(TEST_KEY),.done(key_exp_done),.round_keys(round_keys));
    cipher u_enc (.clk(slow_clk),.rst_n(rst_n),.start(enc_start),
        .plaintext(TEST_PT),.round_keys(round_keys),.done(enc_done),.ciphertext(ciphertext));
    inv_cipher u_dec (.clk(slow_clk),.rst_n(rst_n),.start(dec_start),
        .ciphertext_in(ciphertext),.round_keys(round_keys),.done(dec_done),.plaintext_out(decrypted));
 
    localparam IDLE=3'd0,KEY_EXP=3'd1,ENCRYPT=3'd2,DECRYPT=3'd3,SHOW=3'd4;
    reg [2:0] state;
 
    always @(posedge slow_clk or negedge rst_n) begin
        if (~rst_n) begin
            state<=IDLE; key_exp_start<=0; enc_start<=0; dec_start<=0; done<=0; led<=0;
        end else begin
            key_exp_start<=1'b0; enc_start<=1'b0; dec_start<=1'b0; // FIX B6
            case (state)
                IDLE:    begin done<=0; if(start) begin key_exp_start<=1; state<=KEY_EXP; end end
                KEY_EXP: if(key_exp_done) begin enc_start<=1; state<=ENCRYPT; end
                ENCRYPT: if(enc_done)     begin dec_start<=1; state<=DECRYPT; end
                DECRYPT: if(dec_done)                          state<=SHOW;
                SHOW:    begin done<=1; led<=decrypted[127:120]; state<=IDLE; end // FIX B5
                default: state<=IDLE;
            endcase
        end
    end
 
    assign dbg_key=TEST_KEY; assign dbg_plaintext=TEST_PT;
    assign dbg_ciphertext=ciphertext; assign dbg_decrypted=decrypted;
    assign dbg_state=state;
endmodule