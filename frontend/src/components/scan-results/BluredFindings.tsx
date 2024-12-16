import { type FC } from "react";

import Finding from "./Finding";

const mockFinding = {
  Issue: "Lorem ipsum odor amet",
  Description: `Lorem ipsum odor amet, consectetuer adipiscing elit. Vulputate iaculis luctus diam rhoncus lacus magna
        tincidunt. Laoreet sem fusce feugiat; pulvinar potenti proin tortor. Id mauris purus euismod facilisis leo
        dignissim iaculis interdum. Sem ullamcorper varius tempor habitant sagittis senectus torquent nunc duis. Ante
        habitant commodo varius ex tincidunt. Libero rhoncus turpis sed sem volutpat sed lectus. Mus ullamcorper
        bibendum primis aptent quis est. Enim molestie tempor bibendum a accumsan lacus magnis. Nisl vitae enim proin
        metus eros vehicula inceptos. Cubilia curabitur iaculis viverra blandit hendrerit nam nibh rhoncus? Nisl pretium
        cubilia consectetur efficitur proin ac cras praesent. Eget massa massa litora sit primis ac ut. In consectetur
        phasellus suspendisse dapibus vitae pulvinar lectus. Parturient ac commodo aptent aptent a sociosqu pretium.
        Sodales litora facilisis quis maximus arcu, et proin urna. Facilisis maecenas cras vitae convallis, quisque
        porttitor? Vestibulum accumsan curabitur placerat aliquet sem massa. Torquent in neque fermentum nullam
        convallis ultrices. Dapibus dictumst tristique leo consequat orci. Egestas primis porta molestie justo nunc
        amet. Donec magnis nunc cras a mus enim mus lacinia? Nunc tortor conubia facilisis potenti primis metus fusce
        donec. Euismod natoque id mauris magnis, dictum metus pretium. Finibus nisl blandit vivamus montes fermentum
        ornare. Curabitur quam donec dis, nascetur velit magnis porttitor. Est libero nascetur lacus cubilia curae
        venenatis; dignissim phasellus mi. Lacinia vulputate viverra arcu augue in. Ex euismod non posuere morbi
        eleifend egestas velit. Semper litora fermentum tempus aenean donec suscipit ad quisque. Porta finibus taciti
        molestie ante consequat non blandit aliquam. Libero porta tempor conubia gravida risus. Hac duis auctor mauris
        convallis ex felis ridiculus. Tristique mus neque bibendum bibendum potenti non. Eget justo pharetra; ante ac
        gravida metus commodo. Tempus lobortis lacinia eros iaculis urna. Conubia natoque posuere potenti lacinia
        elementum per. Interdum consequat convallis iaculis vivamus mus vehicula mi ad sed. Egestas venenatis rhoncus
        tempus convallis vulputate class. Tempus taciti maecenas et dui tortor mus euismod eget. Phasellus himenaeos
        pretium consectetur vestibulum amet tempus mus blandit litora. Vel curae convallis sagittis purus phasellus elit
        maecenas suspendisse. Vel aenean finibus commodo duis facilisi lobortis est eros ut. Et faucibus curabitur purus
        velit ex varius mattis euismod eleifend. Elit egestas habitant aptent ullamcorper feugiat erat senectus. Elit
        auctor commodo ridiculus blandit praesent bibendum per blandit non.`,
  Severity: "Critical",
  Contracts: ["Reentrancy vulnerability in the `unpledge`"],
  Recommendation: "",
};

const BluredFindings: FC = () => <Finding finding={mockFinding} isBlurred totalFindings={5} />;

export default BluredFindings;
