import Image from "next/image";

export const STEPS = [
  {
    notSelectedIcon: <Image src="/svg/repository.svg" alt="Repository" width={45} height={45} />,
    selectingIcon: <Image src="/svg/repository_selecting.svg" alt="Repository Selecting" width={45} height={45} />,
    selectedIcon: <Image src="/svg/repository_selected.svg" alt="Repository Selected" width={100} height={100} />,
    label: "Repository",
  },
  {
    notSelectedIcon: <Image src="/svg/branch.svg" alt="Branch" width={45} height={45} />,
    selectingIcon: <Image src="/svg/branch_selecting.svg" alt="Branch Selecting" width={45} height={45} />,
    selectedIcon: <Image src="/svg/branch_selected.svg" alt="Branch Selected" width={60} height={60} />,
    label: "Branch",
  },
  {
    notSelectedIcon: <Image src="/svg/contract.svg" alt="Contract" width={45} height={45} />,
    selectingIcon: <Image src="/svg/contract_selecting.svg" alt="Contract Selecting" width={45} height={45} />,
    selectedIcon: <Image src="/svg/contract_selected.svg" alt="Contract Selected" width={60} height={60} />,
    label: "Contract",
  },
];
