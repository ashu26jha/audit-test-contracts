import Image from "next/image";

export const STEPS = [
  {
    notSelectedIcon: <Image src="/svg/repository.svg" alt="Repository" width={45} height={45} />,
    selectedIcon: <Image src="/svg/repository_selected.svg" alt="Repository Selected" width={45} height={45} />,
    label: "Repository",
  },
  {
    notSelectedIcon: <Image src="/svg/branch.svg" alt="Branch" width={45} height={45} />,
    selectedIcon: <Image src="/svg/branch_selected.svg" alt="Branch Selected" width={45} height={45} />,
    label: "Branch",
  },
  {
    notSelectedIcon: <Image src="/svg/contract.svg" alt="Contract" width={35} height={35} />,
    selectedIcon: <Image src="/svg/contract_selected.svg" alt="Contract Selected" width={35} height={35} />,
    label: "Contract",
  },
  {
    notSelectedIcon: <Image src="/svg/docs.svg" alt="Docs" width={45} height={45} />,
    selectedIcon: <Image src="/svg/docs_selected.svg" alt="Docs Selected" width={45} height={45} />,
    label: "Docs",
  },
  {
    notSelectedIcon: <Image src="/svg/docs.svg" alt="Docs" width={45} height={45} />,
    selectedIcon: <Image src="/svg/docs_selected.svg" alt="Docs Selected" width={45} height={45} />,
    label: "QnA",
  },
];

export const PLAN_STEP = {
  notSelectedIcon: <Image src="/svg/subscription.svg" alt="Plans" width={45} height={45} />,
  selectedIcon: <Image src="/svg/subscription_selected.svg" alt="Plans Selected" width={45} height={45} />,
  label: "Plans",
};

export const INVARIANTS_STEP = {
  notSelectedIcon: <Image src="/svg/docs.svg" alt="Invariants" width={45} height={45} />,
  selectedIcon: <Image src="/svg/docs_selected.svg" alt="Invariants Selected" width={45} height={45} />,
  label: "Invariants",
};
