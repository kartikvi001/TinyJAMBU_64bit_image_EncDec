`timescale 1ns/1ps

module mux_2to1(in0, in1, sel, out);
    input in0, in1, sel;
    output reg out;
    always @(*) begin
        out = sel ? in1 : in0; //if sel is 1 then, out = in1; and if sel is 0 the out = in0;
    end
endmodule //ok & tested


module mux_4to3(in0, in1, in2, in3, sel, out);
    input[2:0] in0, in1, in2, in3;
    input[1:0] sel;
    output reg[2:0] out;
    always @(*) begin
        case (sel)
           2'b00 : out = in0;
           2'b01 : out = in1;
           2'b10 : out = in2;
           2'b11 : out = in3; 
            default: out = 3'b0;
        endcase 
    end
endmodule //ok & tested


module CiTagmux_4to1(in0, in1, in2, in3, sel, out);
    input[31:0] in0, in1, in2, in3;
    input[1:0] sel;
    output reg[31:0] out;
    always @(*) begin
        case (sel)
           2'b00 : out = in0;
           2'b01 : out = in1;
           2'b10 : out = in2;
           2'b11 : out = in3; 
            default: out = 32'b0;
        endcase 
    end
endmodule //ok & tested 


module mux_8to1(in0, in1, in2, in3, in4, in5, in6, in7, sel, out);
    input[31:0] in0, in1, in2, in3, in4, in5, in6, in7;
    input[2:0] sel;
    output reg[31:0] out;
    always @(*) begin
        case (sel)
           3'b000 : out = in0; 
           3'b001 : out = in1; 
           3'b010 : out = in2; 
           3'b011 : out = in3; 
           3'b100 : out = in4; 
           3'b101 : out = in5; 
           3'b110 : out = in6; 
           3'b111 : out = in7; 
            default: out = 32'b0;
        endcase 
    end
endmodule //ok & tested 


module counter_11bit (bit11_countdone, bit11_cnt, rst_11bit, cl, en_11bit, bit11cntTill);
    input cl, rst_11bit, en_11bit; 
    input[10:0] bit11cntTill;
    output reg[10:0] bit11_cnt;
    output reg bit11_countdone;

    always @(posedge cl or posedge rst_11bit) begin
        if(rst_11bit) begin bit11_cnt <= 11'd0;end
        else if(en_11bit) begin 
            if(bit11_cnt != bit11cntTill-1) begin bit11_cnt <= bit11_cnt + 1'b1;end
            else begin bit11_cnt <= 11'd1;end
        end
        else begin bit11_cnt <= bit11_cnt;end
    end

    always @(*) begin
        if((en_11bit==1)&&(bit11_cnt == bit11cntTill-1)) bit11_countdone <=1;
        else bit11_countdone <=0;
    end
endmodule //ok & tested


module reg_file (reg_add, write_data, write_en, clk);   ///without read ports, we just have to write 
    input [1:0]  reg_add;
    input [31:0] write_data;
    input write_en, clk;
    reg [31:0] reg_mem [3:0];  //to store two 32 bits cipherText parts and two 32 bits authTag parts

    // initial
    // begin
    //     // $readmemh("reg_mem_img.dat", reg_mem);
    //     #80000 $writememh("reg_mem_img.dat", reg_mem);
    // end

    always @ (posedge clk)
    begin
        if(write_en)begin 
            reg_mem[reg_add] = write_data;
            // $writememh("reg_mem_img.dat", reg_mem);
        end
        else
            reg_mem[reg_add] <= reg_mem[reg_add];
    end
endmodule //ok & tested


module stateUpdate(state, key, clk, i, state_rst, inp_st, reg_write, update_en);
    input[127:0] key, inp_st;
    input clk, state_rst, update_en;
    input reg_write;
    input[10:0] i; //11 bit counter
    output reg[127:0] state;
    reg feedback;
    reg [6:0] iModKlen;
    
    always @(posedge clk) begin
        if(state_rst) state <= 127'd0;
        else if(reg_write) state <= inp_st;
        else if(update_en) begin
            feedback = state[0] ^ state[47] ^ (~(state[70]&state[85])) ^ state[91] ^ key[iModKlen];
            state[126:0] = state[127:1];
            state[127] = feedback;
        end
		else state <= state;
    end

    always @(*) begin
        iModKlen  = i[6:0]; //klen is 128 bit hence, i  mod klen = last 7 bits of i
    end
endmodule // ok & tested


///////////////////////////////  MAIN   MODULE  //////////////////////////////
module main_module (presentState, cipher_xorout, state, clk, rst, ad, msg, key, nonce);
    input clk, rst;
    input[127:0] key;
    input[95:0] nonce; 
    input[63:0] ad, msg;
    wire[31:0] cipher_xorout;
    wire[127:0] state;
    wire[4:0] presentState;

    wire t1, t2, t3, out38, out37, out36, bit11_countdone;
    wire[2:0] frameBits;
    wire[10:0] bit11cntTill, bit11_cnt;
    wire[31:0] non_ad_m_muxOut, temp_xorout, xor_state_muxOut, ciTag_muxout;

    //control signals
    wire rst_11bit, en_11bit, S127to96_xor_st_sel, S36to38_sel, state_rst, reg_write, update_en, write_en;
    wire[2:0] Snon_ad_m_sel;
    wire[1:0] f_sel, Sreg_add_sel;

    control_path    cu_module        (presentState, bit11cntTill, bit11_countdone, clk, rst, rst_11bit, en_11bit, S127to96_xor_st_sel, S36to38_sel, state_rst, reg_write, update_en, write_en, Snon_ad_m_sel, f_sel, Sreg_add_sel);
    mux_4to3        framebit_mux     (.in0(3'd1), .in1(3'd3), .in2(3'd5), .in3(3'd7), .sel(f_sel), .out(frameBits));
    xor        xor1                  (t1, frameBits[2], state[38]);
    xor        xor2                  (t2, frameBits[1], state[37]);
    xor        xor3                  (t3, frameBits[0], state[36]);
    mux_2to1        state38to36_mux1 (.in1(t1), .in0(state[38]), .sel(S36to38_sel), .out(out38));
    mux_2to1        state38to36_mux2 (.in1(t2), .in0(state[37]), .sel(S36to38_sel), .out(out37));
    mux_2to1        state38to36_mux3 (.in1(t3), .in0(state[36]), .sel(S36to38_sel), .out(out36));
    counter_11bit   toCount1024Rounds(.bit11_countdone(bit11_countdone), .bit11_cnt(bit11_cnt), .rst_11bit(rst_11bit), .cl(clk), .en_11bit(en_11bit), .bit11cntTill(bit11cntTill));

    mux_8to1        non_ad_mSel      (.in0(nonce[31:0]), .in1(nonce[63:32]), .in2(nonce[95:64]), .in3(ad[31:0]), .in4(ad[63:32]), .in5(msg[31:0]), .in6(msg[63:32]), .in7(32'd0), .sel(Snon_ad_m_sel), .out(non_ad_m_muxOut));
    generate
        for (genvar j = 0; j<32; j=j+1) begin
            xor       xor_n                  (temp_xorout[j], non_ad_m_muxOut[j], state[96+j]);  
        end
    endgenerate
    generate
        for (genvar j = 0; j<32; j=j+1) begin
            mux_2to1        temp_xorout_orSt (.in0(state[96+j]), .in1(temp_xorout[j]), .sel(S127to96_xor_st_sel), .out(xor_state_muxOut[j]));  //this is xor gate of nonce
        end
    endgenerate  
    stateUpdate     stUpdate        (.state(state), .key(key), .clk(clk), .i(bit11_cnt), .state_rst(state_rst),
                                     .inp_st({xor_state_muxOut, state[95:39], out38, out37, out36, state[35:0]}),
                                    .reg_write(reg_write), .update_en(update_en));
    generate
        for (genvar j = 0; j<32; j=j+1) begin
            xor        cipher_xorout         (cipher_xorout[j], state[64+j], non_ad_m_muxOut[j]); 
        end
    endgenerate                                 
    CiTagmux_4to1           ciTag_mux (.in0(cipher_xorout[31:0]), .in1(cipher_xorout[31:0]), .in2(state[95:64]), .in3(state[95:64]), .sel(Sreg_add_sel), .out(ciTag_muxout));
    reg_file                forCiTag  (.reg_add(Sreg_add_sel), .write_data(ciTag_muxout), .write_en(write_en), .clk(clk));
endmodule


///////////////////////////////  CONTROL PATH  MODULE  //////////////////////////////
module control_path(presentState, bit11cntTill, bit11_countdone, clk, rst, rst_11bit, en_11bit, S127to96_xor_st_sel, S36to38_sel, state_rst, reg_write, update_en, write_en, Snon_ad_m_sel, f_sel, Sreg_add_sel);
    input clk, rst, bit11_countdone;
    output reg rst_11bit, en_11bit, S127to96_xor_st_sel, S36to38_sel, state_rst, reg_write, update_en, write_en;
    output reg[2:0] Snon_ad_m_sel;
    output reg[1:0] f_sel, Sreg_add_sel;
    output reg[4:0]  presentState;
    output reg[10:0] bit11cntTill;
    reg[4:0] nextState; 

    parameter   ps1=5'd1, ps2=5'd2,
                ps3i0=5'd3, ps4i0=5'd4, ps5i0=5'd5,
                ps3i1=5'd6, ps4i1=5'd7, ps5i1=5'd8,
                ps3i2=5'd9, ps4i2=5'd10, ps5i2=5'd11,
                ps6i0=5'd12, ps7i0=5'd13, ps8i0=5'd14,
                ps6i1=5'd15, ps7i1=5'd16, ps8i1=5'd17,
                ps9i0=5'd18, ps10i0=5'd19, ps11i0=5'd20, ps12i0=5'd21,
                ps9i1=5'd22, ps10i1=5'd23, ps11i1=5'd24, ps12i1=5'd25,
                ps13 =5'd26, ps14  =5'd27, ps15  =5'd28, ps16  =5'd29,
                ps17 =5'd30, ps18  =5'd31;
    always @(posedge clk) 
    begin
        if(rst) begin 
            presentState    <= ps1;         
        end 
        else begin
            presentState    <= nextState;
        end
    end

    always @(*) 
    begin
        case (presentState)
    /////////////////////////initialization step - key setup////////////////////////////
            ps1: //resetting the state, and setting up 11bitcounter to 1024
            begin
                state_rst           <= 1'b1;
                bit11cntTill        <= 11'd1024;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b0;
                update_en           <= 1'b0;
                f_sel               <= 2'd0;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps2;
            end

            ps2: //doing p1024
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd1024;
                rst_11bit           <= 1'b0;
                en_11bit            <= 1'b1;

                reg_write           <= 1'b0;
                update_en           <= 1'b1;
                f_sel               <= 2'd0;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                case (bit11_countdone)
                    1'b0 : nextState = ps2;
                    1'b1 : nextState = ps3i0; 
                    default: nextState = ps3i0;
                endcase
            end

    /////////////////////////initialization step - nonce setup////////////////////////////
            //round i=0 
            ps3i0: //framebits xor & setting counter for p640
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd0;
                S36to38_sel         <= 1'b1;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps4i0;
            end

            ps4i0: //doing p640
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b0;
                en_11bit            <= 1'b1;

                reg_write           <= 1'b0;
                update_en           <= 1'b1;
                f_sel               <= 2'd0;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                case (bit11_countdone)
                    1'b0 : nextState = ps4i0;
                    1'b1 : nextState = ps5i0; 
                    default: nextState = ps5i0;
                endcase
            end

            ps5i0: //nonce xor
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd0;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd0;
                S127to96_xor_st_sel <= 1'b1;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps3i1;
            end

            //round i=1
            ps3i1: //framebits xor & setting counter for p640
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd0;
                S36to38_sel         <= 1'b1;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps4i1;
            end

            ps4i1: //doing p640
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b0;
                en_11bit            <= 1'b1;

                reg_write           <= 1'b0;
                update_en           <= 1'b1;
                f_sel               <= 2'd0;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                case (bit11_countdone)
                    1'b0 : nextState = ps4i1;
                    1'b1 : nextState = ps5i1; 
                    default: nextState = ps5i1;
                endcase
            end

            ps5i1: //nonce xor
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd0;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd1;
                S127to96_xor_st_sel <= 1'b1;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps3i2;
            end

            //round i=2 
            ps3i2: //framebits xor & setting counter for p640
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd0;
                S36to38_sel         <= 1'b1;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps4i2;
            end

            ps4i2: //doing p640
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b0;
                en_11bit            <= 1'b1;

                reg_write           <= 1'b0;
                update_en           <= 1'b1;
                f_sel               <= 2'd0;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                case (bit11_countdone)
                    1'b0 : nextState = ps4i2;
                    1'b1 : nextState = ps5i2; 
                    default: nextState = ps5i2;
                endcase
            end

            ps5i2: //nonce xor
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd0;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd2;
                S127to96_xor_st_sel <= 1'b1;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps6i0;
            end

    /////////////////////////processing the associated data-full blocks////////////////////////////
            //round i=0 
            ps6i0: //framebits xor & setting counter for p640
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd1;
                S36to38_sel         <= 1'b1;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps7i0;
            end

            ps7i0: //doing p640
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b0;
                en_11bit            <= 1'b1;

                reg_write           <= 1'b0;
                update_en           <= 1'b1;
                f_sel               <= 2'd1;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                case (bit11_countdone)
                    1'b0 : nextState = ps7i0;
                    1'b1 : nextState = ps8i0; 
                    default: nextState = ps8i0;
                endcase
            end

            ps8i0: //ad xor
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd1;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd3;
                S127to96_xor_st_sel <= 1'b1;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps6i1;
            end

            //round i=1
            ps6i1: //framebits xor & setting counter for p640
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd1;
                S36to38_sel         <= 1'b1;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps7i1;
            end

            ps7i1: //doing p640
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b0;
                en_11bit            <= 1'b1;

                reg_write           <= 1'b0;
                update_en           <= 1'b1;
                f_sel               <= 2'd1;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                case (bit11_countdone)
                    1'b0 : nextState = ps7i1;
                    1'b1 : nextState = ps8i1; 
                    default: nextState = ps8i1;
                endcase
            end

            ps8i1: //ad xor
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd1;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd4;
                S127to96_xor_st_sel <= 1'b1;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps9i0;
            end

    /////////////////////////processing the plain text-full blocks////////////////////////////
            //round i=0 
            ps9i0: //framebits xor & setting counter for p1024
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd1024;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd2;
                S36to38_sel         <= 1'b1;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps10i0;
            end

            ps10i0: //doing p1024
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd1024;
                rst_11bit           <= 1'b0;
                en_11bit            <= 1'b1;

                reg_write           <= 1'b0;
                update_en           <= 1'b1;
                f_sel               <= 2'd2;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                case (bit11_countdone)
                    1'b0 : nextState = ps10i0;
                    1'b1 : nextState = ps11i0; 
                    default: nextState = ps11i0;
                endcase
            end

            ps11i0: //msg xor
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd1024;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd2;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd5;
                S127to96_xor_st_sel <= 1'b1;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps12i0;
            end

            ps12i0: //storing ci[31:0] in reg file
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd1024;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b0;
                update_en           <= 1'b0;
                f_sel               <= 2'd2;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd5;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b1;  //is it writing in reg file?
                Sreg_add_sel        <= 2'd1;

                nextState           <= ps9i1;
            end

            //round i=1
            ps9i1: //framebits xor & setting counter for p1024
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd1024;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd2;
                S36to38_sel         <= 1'b1;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps10i1;
            end

            ps10i1: //doing p1024
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd1024;
                rst_11bit           <= 1'b0;
                en_11bit            <= 1'b1;

                reg_write           <= 1'b0;
                update_en           <= 1'b1;
                f_sel               <= 2'd2;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                case (bit11_countdone)
                    1'b0 : nextState = ps10i1;
                    1'b1 : nextState = ps11i1; 
                    default: nextState = ps11i1;
                endcase
            end

            ps11i1: //msg xor
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd1024;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd2;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd6;
                S127to96_xor_st_sel <= 1'b1;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps12i1;
            end

            ps12i1: //storing ci[63:32] in reg file
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd1024;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b0;
                update_en           <= 1'b0;
                f_sel               <= 2'd2;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd6;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b1;  //is it writing in reg file?
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps13;
            end

    /////////////////////////The finalization////////////////////////////
            ps13: //framebits xor & setting counter for p1024
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd1024;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd3;
                S36to38_sel         <= 1'b1;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps14;
            end


            ps14: //doing p1024
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd1024;
                rst_11bit           <= 1'b0;
                en_11bit            <= 1'b1;

                reg_write           <= 1'b0;
                update_en           <= 1'b1;
                f_sel               <= 2'd3;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                case (bit11_countdone)
                    1'b0 : nextState = ps14;
                    1'b1 : nextState = ps15; 
                    default: nextState = ps15;
                endcase
            end

            ps15: //storing tag[31:0] in reg file
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b0;
                update_en           <= 1'b0;
                f_sel               <= 2'd3;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b1;  //is it writing in reg file?
                Sreg_add_sel        <= 2'd3;

                nextState           <= ps16;
            end

            ps16: //framebits xor & setting counter for p640
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b1;
                update_en           <= 1'b0;
                f_sel               <= 2'd3;
                S36to38_sel         <= 1'b1;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                nextState           <= ps17;
            end

            ps17: //doing p640
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b0;
                en_11bit            <= 1'b1;

                reg_write           <= 1'b0;
                update_en           <= 1'b1;
                f_sel               <= 2'd3;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd6;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b0;
                Sreg_add_sel        <= 2'd0;

                case (bit11_countdone)
                    1'b0 : nextState = ps17;
                    1'b1 : nextState = ps18; 
                    default: nextState = ps18;
                endcase
            end            

            ps18: //storing tag[63:32] in reg file
            begin
                state_rst           <= 1'b0;
                bit11cntTill        <= 11'd640;
                rst_11bit           <= 1'b1;
                en_11bit            <= 1'b0;

                reg_write           <= 1'b0;
                update_en           <= 1'b0;
                f_sel               <= 2'd3;
                S36to38_sel         <= 1'b0;
                Snon_ad_m_sel       <= 3'd7;
                S127to96_xor_st_sel <= 1'b0;
                write_en            <= 1'b1;  //is it writing in reg file?
                Sreg_add_sel        <= 2'd2;

                $display("Successfully encrypted the 64-bit msg !");  
            end
            default: $display("default statement");
        endcase
    end
endmodule


///////////////////////////////  TESTBENCH  //////////////////////////////
module tinyJAMBU64bit_testbench();
    wire[31:0] cipher_xorout;
    wire[4:0] presentState;
    wire[127:0] state;
    reg[63:0] ad, msg;   
    reg clk, rst;
    reg[95:0] nonce; 
    reg[127:0] key;

    main_module dut (presentState, cipher_xorout, state, clk, rst, ad, msg, key, nonce); 

    initial begin
        $monitor("Time=%3d, key=%b, ad=%b, msg=%b, nonce=%b, presentState=%d, tag[63:32]=%b", $time, key, ad, msg, nonce, presentState, state[95:64]);
        $dumpfile("tinyJAMBU64bit_testbench.vcd");
        $dumpvars(0, tinyJAMBU64bit_testbench);
    end
    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end
    initial begin
        #80000 $finish; 
    end

    initial begin
        #3 rst=1;
        key=128'd255;
        nonce=96'd155;
        ad = 64'd55; msg=64'd255;
        #5 rst=0;
    end
endmodule
