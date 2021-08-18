<template>
  <v-app>
    <v-main>
      <v-container>
        <v-row>
          <v-col cols="12">
            <v-card>
              <v-card-title>
                RSA暗号化の準備
              </v-card-title>
              <v-card-text>
                <v-row>
                  <v-col>
                    <v-card>
                      <v-card-title>
                        素数を決める
                      </v-card-title>
                      <v-card-subtitle>
                        実際の RSA
                        暗号では巨大な素数を探し出して使用します。巨大な素数を掛け合わせて得られた巨大な数値の因数分解が困難であることが、この暗号化の安全性の担保に繋がります。
                      </v-card-subtitle>
                      <v-card-text>
                        <v-row>
                          <v-col cols="12">
                            <v-text-field
                              class="required"
                              v-model="m.p"
                              label="※ p (素数)"
                            ></v-text-field>
                          </v-col>
                          <v-col cols="12">
                            <v-text-field
                              class="required"
                              v-model="m.q"
                              label="※ q (素数)"
                            ></v-text-field>
                          </v-col>
                          <v-col cols="12">
                            <v-text-field
                              :value="K1"
                              label="K1 (p * q)"
                              readonly
                            ></v-text-field>
                          </v-col>
                        </v-row>
                      </v-card-text>
                    </v-card>
                  </v-col>

                  <v-col>
                    <v-card>
                      <v-card-title>
                        公開鍵の exponent を求める
                      </v-card-title>
                      <v-card-subtitle>
                        処理高速化を理由として 65537 (0x10001)
                        が多く使われるため、実際には「公開鍵の exponent
                        を求める」処理は行われる機会は少ないですが、実際には「R以外の任意の数」です。
                      </v-card-subtitle>
                      <v-card-text>
                        <v-row>
                          <v-col cols="12">
                            <v-text-field
                              :value="m.p - 1"
                              label="p' (p -1)"
                              readonly
                            ></v-text-field>
                          </v-col>
                          <v-col cols="12">
                            <v-text-field
                              :value="m.q - 1"
                              label="q' (q -1)"
                              readonly
                            ></v-text-field>
                          </v-col>
                          <v-col cols="12">
                            <v-text-field
                              :value="R"
                              label="R (p' と q' の最小公倍数)"
                              readonly
                            ></v-text-field>
                          </v-col>
                          <v-col cols="12">
                            <v-text-field
                              class="required"
                              v-model="m.K2"
                              label="※ K2 (R 以外の任意の数)"
                            ></v-text-field>
                          </v-col>
                        </v-row>
                      </v-card-text>
                    </v-card>
                  </v-col>

                  <v-col>
                    <v-card>
                      <v-card-title>
                        秘密鍵の exponent を求める
                      </v-card-title>
                      <v-card-text>
                        <v-row>
                          <v-col cols="12">
                            <v-text-field
                              class="required"
                              v-model="m.n"
                              label="※ n (次行の式が整数になる任意の数)"
                            ></v-text-field>
                          </v-col>
                          <v-col cols="12">
                            <v-text-field
                              v-model="K3"
                              label="K3 ((R * n + 1) / K2)"
                            ></v-text-field>
                          </v-col>
                        </v-row>
                      </v-card-text>
                    </v-card>
                  </v-col>
                </v-row>
              </v-card-text>
            </v-card>
          </v-col>

          <v-col cols="12">
            <v-card>
              <v-card-title>
                RSA暗号の鍵ペア
              </v-card-title>
              <v-card-text>
                <v-row>
                  <v-col>
                    <v-card>
                      <v-card-title>
                        公開鍵
                      </v-card-title>
                      <v-card-text>
                        <v-row>
                          <v-col cols="6">
                            <v-text-field
                              :value="K1"
                              label="K1: modulus"
                              readonly
                            ></v-text-field>
                          </v-col>
                          <v-col cols="6">
                            <v-text-field
                              v-model="m.K2"
                              label="K2: exponent"
                              readonly
                            ></v-text-field>
                          </v-col>
                        </v-row>
                      </v-card-text>
                    </v-card>
                  </v-col>
                  <v-col>
                    <v-card>
                      <v-card-title>
                        秘密鍵
                      </v-card-title>
                      <v-card-text>
                        <v-row>
                          <v-col cols="6">
                            <v-text-field
                              :value="K1"
                              label="K1: modulus"
                              readonly
                            ></v-text-field>
                          </v-col>
                          <v-col cols="6">
                            <v-text-field
                              v-model="K3"
                              label="K3: exponent"
                              readonly
                            ></v-text-field>
                          </v-col>
                        </v-row>
                      </v-card-text>
                    </v-card>
                  </v-col>
                </v-row>
              </v-card-text>
            </v-card>
          </v-col>

          <v-col cols="12">
            <v-card>
              <v-card-title>
                暗号化と復号化
              </v-card-title>
              <v-card-subtitle>
                暗号化、復号化、いずれも x を入力とすると x ** exponent %
                modulus
                を演算するだけで、やることは単純です。（単純ですが、実際は巨大な数値を演算することになるので楽ではないです）
              </v-card-subtitle>
              <v-card-text>
                <v-row>
                  <v-col>
                    <v-card>
                      <v-card-title>
                        公開鍵で暗号化　→　秘密鍵で復号化
                      </v-card-title>
                      <v-card-text>
                        <v-row>
                          <v-col cols="4">
                            <v-text-field
                              v-model="m.ORG1"
                              class="required"
                              label="平文"
                            ></v-text-field>
                          </v-col>
                          <v-col cols="4">
                            <v-text-field
                              :value="ENC1"
                              label="暗号化 (平文 ** K2 % K1) "
                              readonly
                            ></v-text-field>
                          </v-col>
                          <v-col cols="4">
                            <v-text-field
                              :value="DEC1"
                              label="復号化 (暗号文 ** K3 % K1) "
                              readonly
                            ></v-text-field>
                          </v-col>
                        </v-row>
                      </v-card-text>
                    </v-card>
                  </v-col>
                  <v-col>
                    <v-card>
                      <v-card-title>
                        秘密鍵で暗号化　→　公開鍵で復号化
                      </v-card-title>
                      <v-card-text>
                        <v-row>
                          <v-col cols="4">
                            <v-text-field
                              v-model="m.ORG2"
                              class="required"
                              label="平文"
                            ></v-text-field>
                          </v-col>
                          <v-col cols="4">
                            <v-text-field
                              :value="ENC2"
                              label="暗号化 (平文 ** K3 % K1) "
                              readonly
                            ></v-text-field>
                          </v-col>
                          <v-col cols="4">
                            <v-text-field
                              :value="DEC2"
                              label="復号化 (暗号文 ** K2 % K1) "
                              readonly
                            ></v-text-field>
                          </v-col>
                        </v-row>
                      </v-card-text>
                    </v-card>
                  </v-col>
                </v-row>
              </v-card-text>
            </v-card>
          </v-col>
        </v-row>
      </v-container>
    </v-main>
  </v-app>
</template>

<style scoped>
.required {
  background-color: lightblue;
}
</style>

<script lang="ts">
import { computed, defineComponent, reactive } from "@vue/composition-api";
const lcm = require("compute-lcm") as (arr: number[]) => number;

export default defineComponent({
  name: "App",
  setup() {
    const m = reactive({
      p: 3,
      q: 11,
      K2: 3,
      n: 2,

      ORG1: 2,
      ORG2: 2
    });

    const K1 = computed(() => {
      return m.p * m.q;
    });

    const R = computed(() => {
      return lcm([m.p - 1, m.q - 1]);
    });

    const K3 = computed(() => {
      return (R.value * m.n + 1) / m.K2;
    });

    const calc = (value: number, exponent: number, modulus: number) =>
      value ** exponent % modulus;

    const ENC1 = computed(() => {
      return calc(m.ORG1, m.K2, K1.value);
    });

    const DEC1 = computed(() => {
      return calc(ENC1.value, K3.value, K1.value);
    });

    const ENC2 = computed(() => {
      return calc(m.ORG2, K3.value, K1.value);
    });

    const DEC2 = computed(() => {
      return calc(ENC2.value, m.K2, K1.value);
    });

    return {
      m,
      R,
      K1,
      K3,
      ENC1,
      DEC1,
      ENC2,
      DEC2
    };
  }
});
</script>
