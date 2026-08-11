// ============================================================================
// 6. Inverse Cipher (AES-128 Decryption)
//
// InvShiftRows: row r shifts RIGHT by r
//   out_byte[i] = in_byte[ iperm[i] ]
//   iperm = [0,13,10,7, 4,1,14,11, 8,5,2,15, 12,9,6,3]
// ============================================================================
module inv_cipher(
    input          clk,
    input          rst_n,
    input          start,
    input  [127:0] ciphertext_in,
    input  [1407:0] round_keys,
    output reg     done,
    output reg [127:0] plaintext_out
);
    reg [3:0]   round;
    reg [127:0] state;
    reg [2:0]   step;
    integer     j;
 
    wire [7:0] isbox_out [0:15];
    genvar gi;
    generate
        for (gi=0; gi<16; gi=gi+1) begin : isg
            inv_s_box u_isb (.data_in(state[(127-gi*8)-:8]), .data_out(isbox_out[gi]));
        end
    endgenerate
 
    function [7:0] xtime; input [7:0] x;
        xtime={x[6:0],1'b0}^(x[7]?8'h1b:8'h00); endfunction
    function [7:0] mul09; input [7:0] x; mul09=xtime(xtime(xtime(x)))^x; endfunction
    function [7:0] mul0b; input [7:0] x; mul0b=xtime(xtime(xtime(x)))^xtime(x)^x; endfunction
    function [7:0] mul0d; input [7:0] x; mul0d=xtime(xtime(xtime(x)))^xtime(xtime(x))^x; endfunction
    function [7:0] mul0e; input [7:0] x; mul0e=xtime(xtime(xtime(x)))^xtime(xtime(x))^xtime(x); endfunction
 
    function [31:0] inv_mix_col; input [31:0] col;
        reg [7:0] a0,a1,a2,a3; begin
            a0=col[31:24];a1=col[23:16];a2=col[15:8];a3=col[7:0];
            inv_mix_col[31:24]=mul0e(a0)^mul0b(a1)^mul0d(a2)^mul09(a3);
            inv_mix_col[23:16]=mul09(a0)^mul0e(a1)^mul0b(a2)^mul0d(a3);
            inv_mix_col[15:8] =mul0d(a0)^mul09(a1)^mul0e(a2)^mul0b(a3);
            inv_mix_col[7:0]  =mul0b(a0)^mul0d(a1)^mul09(a2)^mul0e(a3);
        end endfunction
 
    always @(posedge clk or negedge rst_n) begin
        if (~rst_n) begin
            round<=4'd0; state<=128'd0; done<=1'b0; plaintext_out<=128'd0; step<=3'd0;
        end else begin
            case (step)
                3'd0: begin done<=1'b0; if(start) begin state<=ciphertext_in; round<=4'd10; step<=3'd1; end end
 
                // Initial ARK with RK10; set round=9 so the loop starts at RK9
                // BUG FIX B9: round was left at 10, causing step4 to XOR RK10 a
                // second time on the first loop iteration. Correct: start loop at 9.
                3'd1: begin state<=ciphertext_in^round_keys[10*128+:128]; round<=4'd9; step<=3'd2; end
 
                // InvShiftRows - iperm [0,13,10,7, 4,1,14,11, 8,5,2,15, 12,9,6,3]
                3'd2: begin
                    state<={
                        state[127:120],  // b0  ←b0
                        state[23:16],    // b1  ←b13
                        state[47:40],    // b2  ←b10
                        state[71:64],    // b3  ←b7
                        state[95:88],    // b4  ←b4
                        state[119:112],  // b5  ←b1
                        state[15:8],     // b6  ←b14
                        state[39:32],    // b7  ←b11
                        state[63:56],    // b8  ←b8
                        state[87:80],    // b9  ←b5
                        state[111:104],  // b10 ←b2
                        state[7:0],      // b11 ←b15
                        state[31:24],    // b12 ←b12
                        state[55:48],    // b13 ←b9
                        state[79:72],    // b14 ←b6
                        state[103:96]    // b15 ←b3
                    };
                    step<=3'd3;
                end
 
                // InvSubBytes
                3'd3: begin
                    for(j=0;j<16;j=j+1) state[(127-j*8)-:8]<=isbox_out[j];
                    step<=3'd4;
                end
 
                // AddRoundKey
                3'd4: begin
                    if (round==4'd0) begin
                        plaintext_out<=state^round_keys[0+:128]; done<=1'b1; step<=3'd0;
                    end else begin
                        state<=state^round_keys[round*128+:128];
                        round<=round-4'd1; step<=3'd5;
                    end
                end
 
                // InvMixColumns
                3'd5: begin
                    state<={inv_mix_col(state[127:96]),inv_mix_col(state[95:64]),
                            inv_mix_col(state[63:32]), inv_mix_col(state[31:0])};
                    step<=3'd2;
                end
 
                default: step<=3'd0;
            endcase
        end
    end
endmodule