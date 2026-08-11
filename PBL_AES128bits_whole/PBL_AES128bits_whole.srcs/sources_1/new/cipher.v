// ============================================================================
// 5. Cipher (AES-128 Encryption)
//
// Byte layout: state[127:120]=byte0 … state[7:0]=byte15
// AES state matrix (column-major, FIPS-197):
//        col0    col1    col2    col3
//  row0: b0      b4      b8      b12
//  row1: b1      b5      b9      b13
//  row2: b2      b6      b10     b14
//  row3: b3      b7      b11     b15
//
// ShiftRows: row r shifts LEFT by r
//   out_byte[i] = in_byte[ perm[i] ]
//   perm = [0,5,10,15, 4,9,14,3, 8,13,2,7, 12,1,6,11]
//   Verified against NIST FIPS-197 App B round-1 intermediate values.
// ============================================================================
module cipher(
    input          clk,
    input          rst_n,
    input          start,
    input  [127:0] plaintext,
    input  [1407:0] round_keys,
    output reg     done,
    output reg [127:0] ciphertext
);
    reg [3:0]   round;
    reg [127:0] state;
    reg [2:0]   step;
    integer     j;
 
    wire [7:0] sbox_out [0:15];
    genvar gi;
    generate
        for (gi=0; gi<16; gi=gi+1) begin : sg
            s_box u_sb (.data_in(state[(127-gi*8) -: 8]), .data_out(sbox_out[gi]));
        end
    endgenerate
 
    function [7:0] xtime; input [7:0] x;
        xtime={x[6:0],1'b0}^(x[7]?8'h1b:8'h00); endfunction
 
    function [31:0] mix_col; input [31:0] col;
        reg [7:0] a0,a1,a2,a3; begin
            a0=col[31:24];a1=col[23:16];a2=col[15:8];a3=col[7:0];
            mix_col[31:24]=xtime(a0)^(xtime(a1)^a1)^a2^a3;
            mix_col[23:16]=a0^xtime(a1)^(xtime(a2)^a2)^a3;
            mix_col[15:8] =a0^a1^xtime(a2)^(xtime(a3)^a3);
            mix_col[7:0]  =(xtime(a0)^a0)^a1^a2^xtime(a3);
        end endfunction
 
    always @(posedge clk or negedge rst_n) begin
        if (~rst_n) begin
            round<=4'd0; state<=128'd0; done<=1'b0; ciphertext<=128'd0; step<=3'd0;
        end else begin
            case (step)
                // IDLE
                3'd0: begin done<=1'b0; if(start) begin state<=plaintext; round<=4'd0; step<=3'd1; end end
 
                // Initial ARK with RK0
                3'd1: begin state<=plaintext^round_keys[0+:128]; round<=4'd1; step<=3'd2; end
 
                // SubBytes
                3'd2: begin
                    for(j=0;j<16;j=j+1) state[(127-j*8)-:8]<=sbox_out[j];
                    step<=3'd3;
                end
 
                // ShiftRows - perm [0,5,10,15, 4,9,14,3, 8,13,2,7, 12,1,6,11]
                3'd3: begin
                    state<={
                        state[127:120],  // b0  ←b0
                        state[87:80],    // b1  ←b5
                        state[47:40],    // b2  ←b10
                        state[7:0],      // b3  ←b15
                        state[95:88],    // b4  ←b4
                        state[55:48],    // b5  ←b9
                        state[15:8],     // b6  ←b14
                        state[103:96],   // b7  ←b3
                        state[63:56],    // b8  ←b8
                        state[23:16],    // b9  ←b13
                        state[111:104],  // b10 ←b2
                        state[71:64],    // b11 ←b7
                        state[31:24],    // b12 ←b12
                        state[119:112],  // b13 ←b1
                        state[79:72],    // b14 ←b6
                        state[39:32]     // b15 ←b11
                    };
                    step<=3'd4;
                end
 
                // MixColumns (rounds 1-9) or final ARK (round 10)
                3'd4: begin
                    if (round==4'd10) begin
                        state<=state^round_keys[10*128+:128]; step<=3'd5;
                    end else begin
                        state<={mix_col(state[127:96]),mix_col(state[95:64]),
                                mix_col(state[63:32]), mix_col(state[31:0])};
                        step<=3'd5;
                    end
                end
 
                // ARK (rounds 1-9) or finish (round 10)
                3'd5: begin
                    if (round==4'd10) begin
                        ciphertext<=state; done<=1'b1; step<=3'd0;
                    end else begin
                        // FIX B2: XOR THEN increment round
                        state<=state^round_keys[round*128+:128];
                        round<=round+4'd1; step<=3'd2;
                    end
                end
 
                default: step<=3'd0;
            endcase
        end
    end
endmodule