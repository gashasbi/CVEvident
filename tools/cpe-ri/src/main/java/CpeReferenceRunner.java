import gov.nist.secauto.cpe.common.WellFormedName;
import gov.nist.secauto.cpe.matching.CPENameMatcher;
import gov.nist.secauto.cpe.matching.Relation;
import gov.nist.secauto.cpe.naming.CPENameUnbinder;

import java.text.ParseException;
import java.util.Map;
import java.util.Scanner;

public final class CpeReferenceRunner {
    private CpeReferenceRunner() {
    }

    public static void main(String[] args) {
        Scanner input = new Scanner(System.in, "UTF-8");
        while (input.hasNextLine()) {
            String[] pair = input.nextLine().split("\\t", -1);
            if (pair.length != 2) {
                System.out.println("INVALID");
                continue;
            }
            try {
                WellFormedName source = CPENameUnbinder.unbindFS(pair[0]);
                WellFormedName target = CPENameUnbinder.unbindFS(pair[1]);
                Map<WellFormedName.Attribute, Relation> relations =
                        CPENameMatcher.compareWFNs(source, target);
                StringBuilder output = new StringBuilder();
                String overall = overall(relations);
                output.append(overall);
                for (Relation relation : relations.values()) {
                    output.append('\t').append(relation.name().toLowerCase());
                }
                System.out.println(output);
            } catch (ParseException | RuntimeException exception) {
                System.out.println("INVALID");
            }
        }
    }

    private static String overall(Map<WellFormedName.Attribute, Relation> relations) {
        boolean allEqual = true;
        boolean allSubset = true;
        boolean allSuperset = true;
        for (Relation relation : relations.values()) {
            if (relation == Relation.DISJOINT) {
                return "disjoint";
            }
            allEqual &= relation == Relation.EQUAL;
            allSubset &= relation == Relation.SUBSET || relation == Relation.EQUAL;
            allSuperset &= relation == Relation.SUPERSET || relation == Relation.EQUAL;
        }
        if (allEqual) {
            return "equal";
        }
        if (allSubset) {
            return "subset";
        }
        if (allSuperset) {
            return "superset";
        }
        return "undefined";
    }
}
