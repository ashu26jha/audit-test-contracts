import Image from "next/image";

export const STEPS = [
  {
    notSelectedIcon: <Image src="/repository.svg" alt="Repository" width={45} height={45} />,
    selectingIcon: <Image src="/repository_selecting.svg" alt="Repository Selecting" width={45} height={45} />,
    selectedIcon: <Image src="/repository_selected.svg" alt="Repository Selected" width={100} height={100} />,
    label: "Repository",
  },
  {
    notSelectedIcon: <Image src="/branch.svg" alt="Branch" width={45} height={45} />,
    selectingIcon: <Image src="/branch_selecting.svg" alt="Branch Selecting" width={45} height={45} />,
    selectedIcon: <Image src="/branch_selected.svg" alt="Branch Selected" width={60} height={60} />,
    label: "Branch",
  },
  {
    notSelectedIcon: <Image src="/contract.svg" alt="Contract" width={45} height={45} />,
    selectingIcon: <Image src="/contract_selecting.svg" alt="Contract Selecting" width={45} height={45} />,
    selectedIcon: <Image src="/contract_selected.svg" alt="Contract Selected" width={60} height={60} />,
    label: "Contract",
  },
];
