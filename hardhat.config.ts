import 'hardhat-deploy';
import 'hardhat-deploy-ethers';
import './tasks';
import 'hardhat-contract-sizer';
import 'solidity-docgen';
import '@nomicfoundation/hardhat-foundry';

require('dotenv').config();

const PRIVATE_KEY = process.env.PRIVATE_KEY || '';
const config = {
  solidity: {
    version: '0.8.18',
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {
      chainId: 31337,

      forking: {
        url: 'https://rpc.soniclabs.com',
      },
    },
    sonic: {
      chainId: 146,
      url: 'https://rpc.soniclabs.com',
      accounts: [PRIVATE_KEY],
      verify: {
        etherscan: {
          apiKey: process.env.SONICSCAN_API_KEY,
          apiUrl: 'https://api.sonicscan.org',
        },
      },
    },
    localhost: {
      chainId: 31337,
      url: 'http://localhost:8545',
      accounts: [PRIVATE_KEY],
    },
  },

  namedAccounts: {
    deployer: {
      default: 0,
    },
  },

  docgen: {
    pages: 'files',
  },
};

export default config;
