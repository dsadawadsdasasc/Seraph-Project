#include "bones.h"

BoneHierarchyMap Bones_GetIndices(int boneCount)
{
    BoneHierarchyMap map = { -1, -1, -1, -1 };
    
    switch (boneCount) {
        case 22:
            map.head = 13;
            map.neck = 9;
            map.chest = 8;
            map.pelvis = 0;
            break;
        case 24:
            map.head = 15;
            map.neck = 9;
            map.chest = 8;
            map.pelvis = 0;
            break;
        case 25:
            map.head = 15;
            map.neck = 12;
            map.chest = 11;
            map.pelvis = 0;
            break;
        case 26:
            map.head = 16;
            map.neck = 13;
            map.chest = 12;
            map.pelvis = 0;
            break;
        case 27:
            map.head = 15;
            map.neck = 12;
            map.chest = 11;
            map.pelvis = 0;
            break;
        case 28:
            map.head = 16;
            map.neck = 13;
            map.chest = 12;
            map.pelvis = 0;
            break;
        case 29:
            map.head = 19;
            map.neck = 16;
            map.chest = 15;
            map.pelvis = 0;
            break;
        case 30:
            map.head = 18;
            map.neck = 13;
            map.chest = 11;
            map.pelvis = 0;
            break;
        case 31:
            map.head = 20;
            map.neck = 10;
            map.chest = 8;
            map.pelvis = 0;
            break;
        case 32:
            map.head = 17;
            map.neck = 12;
            map.chest = 11;
            map.pelvis = 0;
            break;
        case 33:
            map.head = 20;
            map.neck = 10;
            map.chest = 8;
            map.pelvis = 0;
            break;
        case 35:
            map.head = 17;
            map.neck = 12;
            map.chest = 11;
            map.pelvis = 0;
            break;
        case 36:
            map.head = 18;
            map.neck = 13;
            map.chest = 12;
            map.pelvis = 0;
            break;
        case 37:
            map.head = 20;
            map.neck = 10;
            map.chest = 8;
            map.pelvis = 0;
            break;
        case 40:
            map.head = 19;
            map.neck = 12;
            map.chest = 11;
            map.pelvis = 0;
            break;
        case 41:
            map.head = 18;
            map.neck = 13;
            map.chest = 12;
            map.pelvis = 0;
            break;
        case 42:
            map.head = 23;
            map.neck = 11;
            map.chest = 10;
            map.pelvis = 0;
            break;
        case 43:
            map.head = 23;
            map.neck = 12;
            map.chest = 11;
            map.pelvis = 0;
            break;
        case 45:
            map.head = 17;
            map.neck = 12;
            map.chest = 11;
            map.pelvis = 0;
            break;
        case 46:
            map.head = 17;
            map.neck = 12;
            map.chest = 11;
            map.pelvis = 0;
            break;
        case 50:
            map.head = 40;
            map.neck = 32;
            map.chest = 29;
            map.pelvis = 0;
            break;
        case 54:
            map.head = 40;
            map.neck = 30;
            map.chest = 28;
            map.pelvis = 0;
            break;
        case 58:
            map.head = 23;
            map.neck = 15;
            map.chest = 13;
            map.pelvis = 0;
            break;
        case 59:
            map.head = 17;
            map.neck = 12;
            map.chest = 11;
            map.pelvis = 0;
            break;
        case 60:
            map.head = 16;
            map.neck = 11;
            map.chest = 10;
            map.pelvis = 0;
            break;
        case 65:
            map.head = 25;
            map.neck = 18;
            map.chest = 15;
            map.pelvis = 0;
            break;
        case 66:
            map.head = 22;
            map.neck = 15;
            map.chest = 14;
            map.pelvis = 0;
            break;
        case 67:
            map.head = 18;
            map.neck = 13;
            map.chest = 11;
            map.pelvis = 12;
            break;
    }
    
    return map;
}

