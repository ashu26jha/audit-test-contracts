export const WETH9_ADDRESS: Record<string, string> = {
  hardhat: '0x039e2fb66102314ce7b64ce5ce3e5183bc94ad38',
  sonic: '0x039e2fb66102314ce7b64ce5ce3e5183bc94ad38',
};

export const LENDING_POOL_RESERVES: Record<string, Record<string, string>> = {
  sonic: {
    wS: '0x039e2fb66102314ce7b64ce5ce3e5183bc94ad38', // 1n
    wETH: '0x50c42deacd8fc9773493ed674b675be577f2634b',
    ['USDC.e']: '0x29219dd400f2bf60e5a23d13be72b486d4038894',
    USDT: '0x6047828dc181963ba44974801ff68e538da5eaf9',
  },
  hardhat: {
    wS: '0x039e2fb66102314ce7b64ce5ce3e5183bc94ad38',
    ['USDC.e']: '0x29219dd400f2bf60e5a23d13be72b486d4038894',
  },
};
export const TREASURY_ADDRESS: Record<string, string> = {
  sonic: '0x57C41F44aA5b0793a3fE0195F6c879892494109F',
  hardhat: '0x57C41F44aA5b0793a3fE0195F6c879892494109F',
};
export const PERFORMANCE_FEE_RECIPIENT_ADDRESS: Record<string, string> = {
  sonic: '0x57C41F44aA5b0793a3fE0195F6c879892494109F',
  hardhat: '0x57C41F44aA5b0793a3fE0195F6c879892494109F',
};
export const LIQUIDATION_FEE_RECIPIENT_ADDRESS: Record<string, string> = {
  sonic: '0x57C41F44aA5b0793a3fE0195F6c879892494109F',
  hardhat: '0x57C41F44aA5b0793a3fE0195F6c879892494109F',
};

export const SHADOW_V3_POSITION_MANAGER_ADDRESS: Record<string, string> = {
  sonic: '0x12E66C8F215DdD5d48d150c8f46aD0c6fB0F4406',
  hardhat: '0x12E66C8F215DdD5d48d150c8f46aD0c6fB0F4406',
};

export const SHADOW_SWAP_ROUTER_ADDRESS: Record<string, string> = {
  sonic: '0x5543c6176feb9b4b179078205d7c29eea2e2d695',
  hardhat: '0x5543c6176feb9b4b179078205d7c29eea2e2d695',
};

export const SWAPX_POSITION_MANAGER_ADDRESS: Record<string, string> = {
  sonic: '0xd82Fe82244ad01AaD671576202F9b46b76fAdFE2',
  hardhat: '0xd82Fe82244ad01AaD671576202F9b46b76fAdFE2',
};

export const SWAPX_SWAP_ROUTER_ADDRESS: Record<string, string> = {
  sonic: '0x037c162092881A249DC347D40Eb84438e3457c02',
  hardhat: '0x037c162092881A249DC347D40Eb84438e3457c02',
};

// https://docs.pyth.network/price-feeds/contract-addresses/evm
export const PYTH_ADDRESS: Record<string, string> = {
  sonic: '0x2880aB155794e7179c9eE2e38200202908C17B43',
  hardhat: '0x2880aB155794e7179c9eE2e38200202908C17B43',
};
export const PYTH_PRICE_IDS: Record<string, Record<string, [string, string]>> = {
  sonic: {
    wS: ['0x039e2fb66102314ce7b64ce5ce3e5183bc94ad38', '0xf490b178d0c85683b7a0f2388b40af2e6f7c90cbe0f96b31f315f08d0e5a2d6d'],
    wETH: ['0x50c42deacd8fc9773493ed674b675be577f2634b', '0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace'],
    ['USDC.e']: ['0x29219dd400f2bf60e5a23d13be72b486d4038894', '0xeaa020c61cc479712813461ce153894a96a6c00b21ed0cfc2798d1f9a9e9c94a'],
    USDT: ['0x6047828dc181963ba44974801ff68e538da5eaf9', '0x2b89b9dc8fdf9f34709a5b106b472f0f39bb6ca9ce04b0fd7f2e971688e2e53b'],
  },
  hardhat: {
    wS: ['0x039e2fb66102314ce7b64ce5ce3e5183bc94ad38', '0xf490b178d0c85683b7a0f2388b40af2e6f7c90cbe0f96b31f315f08d0e5a2d6d'],
    ['USDC.e']: ['0x29219dd400f2bf60e5a23d13be72b486d4038894', '0xeaa020c61cc479712813461ce153894a96a6c00b21ed0cfc2798d1f9a9e9c94a'],
  },
};

export type VaultConfig = {
  liquidationDebtRatio: number;
  gaugeAddress?: string;
  liquidationProtocolFee: number;
  liquidationCallerFeeRatio: number;
  performanceFee: number;
  minPositionSize: string;
  token0ReserveId: number;
  token1ReserveId: number;

  lendingPoolConfig?: {
    vaultId: number;
    borrowEnabled: boolean;
    token0Credit: string;
    token1Credit: string;
  };
};
const maxUint256 = '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const maxUint128 = '0xffffffffffffffffffffffffffffffff';
export const SHADOW_VAULT_CONFIG: Record<string, VaultConfig> = {
  'wS-USDC.e-50': {
    liquidationDebtRatio: 7000,
    gaugeAddress: '0xe879d0e44e6873cf4ab71686055a4f6817685f02',
    liquidationProtocolFee: 500,
    liquidationCallerFeeRatio: 5000, // liqFee 800, liqCallerFee 5000 -> total liqFee 800 + 800*0.5 = 1200
    performanceFee: 1500,
    minPositionSize: '1' + '00000000',
    token0ReserveId: 1,
    token1ReserveId: 3,

    lendingPoolConfig: {
      vaultId: 1,
      borrowEnabled: true,
      token0Credit: maxUint128,
      token1Credit: maxUint128,
    },
  },
  'wS-WETH-50': {
    liquidationDebtRatio: 7000,
    gaugeAddress: '0xf5c7598c953e49755576cda6b2b2a9daaf89a837',
    liquidationProtocolFee: 500,
    liquidationCallerFeeRatio: 5000, // liqFee 800, liqCallerFee 5000 -> total liqFee 800 + 800*0.5 = 1200
    performanceFee: 1500,
    minPositionSize: '1' + '00000000',
    token0ReserveId: 1,
    token1ReserveId: 2,

    lendingPoolConfig: {
      vaultId: 3,
      borrowEnabled: true,
      token0Credit: maxUint128,
      token1Credit: maxUint128,
    },
  },
  'USDC.e-USDT-1': {
    liquidationDebtRatio: 8400,
    gaugeAddress: '0xf3ac5aef4116abfd322fdc683420a4fc4b7f2d73',
    liquidationProtocolFee: 500,
    liquidationCallerFeeRatio: 5000, // liqFee 800, liqCallerFee 5000 -> total liqFee 800 + 800*0.5 = 1200
    performanceFee: 1500,
    minPositionSize: '1' + '00000000',
    token0ReserveId: 3,
    token1ReserveId: 4,

    lendingPoolConfig: {
      vaultId: 4,
      borrowEnabled: true,
      token0Credit: maxUint128,
      token1Credit: maxUint128,
    },
  },
};
// vaultWhitelist
// vaultBorrowCredits
