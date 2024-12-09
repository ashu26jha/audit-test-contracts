import type { FC } from "react";

interface BreadcrumbProps {
  base: string;
  current: string;
}

const Breadcrumb: FC<BreadcrumbProps> = ({ base, current }) => {
  return (
    <div className="text-sm text-gray-400 flex">
      {base} <div className="mx-2">/</div> <div className="text-white">{current}</div>
    </div>
  );
};

export default Breadcrumb;
